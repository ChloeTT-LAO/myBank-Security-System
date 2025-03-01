import numpy as np
import time
import json
import hashlib
import datetime
from typing import Dict, Any, List, Tuple
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from config.mybank_db import Users, UserSessions, SecurityLogs
from security.audit import log_security_event

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

# 用户行为特征权重
FEATURE_WEIGHTS = {
    'login_time': 0.2,  # 登录时间异常性
    'browser_fingerprint': 0.25,  # 浏览器指纹匹配度
    'ip_location': 0.25,  # IP地址位置匹配度
    'typing_pattern': 0.15,  # 击键模式匹配度
    'transaction_pattern': 0.15  # 交易行为模式匹配度
}

# 风险阈值
LOW_RISK_THRESHOLD = 0.7  # 分数高于此值视为低风险
HIGH_RISK_THRESHOLD = 0.4  # 分数低于此值视为高风险


class BehavioralProfiler:
    """用户行为分析器，用于连续认证"""

    def __init__(self, user_id: int):
        self.user_id = user_id
        self.user_profile = self._load_user_profile()
        self.current_session_behavior = {}
        self.current_risk_score = 1.0  # 初始风险分数（最大为1，风险最低）

    def _load_user_profile(self) -> Dict:
        """加载用户的行为特征基线"""
        session = Session()
        try:
            user = session.query(Users).filter_by(user_id=self.user_id).first()
            if not user:
                return self._create_default_profile()

            # 尝试加载现有配置文件
            try:
                if hasattr(user, 'behavioral_profile') and user.behavioral_profile:
                    return json.loads(user.behavioral_profile)
            except:
                pass

            # 如果没有配置文件，创建默认的
            return self._create_default_profile()
        finally:
            session.close()

    def _create_default_profile(self) -> Dict:
        """创建默认的用户行为配置文件"""
        current_time = time.time()
        return {
            'login_times': [],  # 会存储最近10次登录的时间
            'ip_addresses': [],  # 最近使用的IP地址
            'browsers': [],  # 最近使用的浏览器
            'typing_patterns': [],  # 击键节奏模式
            'transaction_patterns': {  # 交易行为模式
                'avg_amount': 0,
                'common_recipients': [],
                'frequency': {}
            },
            'last_updated': current_time,
            'creation_time': current_time,
            'login_count': 0
        }

    def update_login_behavior(self, ip_address: str, user_agent: str, login_time: datetime.datetime) -> None:
        """更新登录行为数据"""
        profile = self.user_profile

        # 更新登录时间
        profile['login_times'].append(login_time.hour)
        if len(profile['login_times']) > 10:
            profile['login_times'] = profile['login_times'][-10:]

        # 更新IP地址
        if ip_address not in profile['ip_addresses']:
            profile['ip_addresses'].append(ip_address)
            if len(profile['ip_addresses']) > 5:
                profile['ip_addresses'] = profile['ip_addresses'][-5:]

        # 更新浏览器信息
        browser_hash = hashlib.md5(user_agent.encode()).hexdigest()
        if browser_hash not in profile['browsers']:
            profile['browsers'].append(browser_hash)
            if len(profile['browsers']) > 3:
                profile['browsers'] = profile['browsers'][-3:]

        # 更新登录计数
        profile['login_count'] += 1
        profile['last_updated'] = time.time()

        # 保存更新后的配置文件
        self._save_profile()

        # 更新当前会话的行为数据
        self.current_session_behavior['login_time'] = login_time.hour
        self.current_session_behavior['ip_address'] = ip_address
        self.current_session_behavior['browser'] = browser_hash

    def update_transaction_behavior(self, transaction_data: Dict) -> None:
        """更新交易行为数据"""
        profile = self.user_profile
        patterns = profile['transaction_patterns']

        # 更新平均交易金额
        amount = float(transaction_data.get('amount', 0))
        if patterns['avg_amount'] == 0:
            patterns['avg_amount'] = amount
        else:
            patterns['avg_amount'] = (patterns['avg_amount'] * 0.9) + (amount * 0.1)

        # 更新常用收款人
        if 'destination_account_id' in transaction_data:
            dest = str(transaction_data['destination_account_id'])
            if dest not in patterns['common_recipients']:
                patterns['common_recipients'].append(dest)
                if len(patterns['common_recipients']) > 10:
                    patterns['common_recipients'] = patterns['common_recipients'][-10:]

        # 更新交易频率
        hour = datetime.datetime.now().hour
        hour_key = str(hour)
        if hour_key in patterns['frequency']:
            patterns['frequency'][hour_key] += 1
        else:
            patterns['frequency'][hour_key] = 1

        profile['last_updated'] = time.time()
        self._save_profile()

        # 更新当前会话的行为数据
        current_tx = self.current_session_behavior.get('transactions', [])
        current_tx.append({
            'amount': amount,
            'destination': transaction_data.get('destination_account_id'),
            'time': hour
        })
        self.current_session_behavior['transactions'] = current_tx

    def calculate_risk_score(self) -> float:
        """计算当前会话的风险分数"""
        if not self.current_session_behavior:
            return 1.0  # 没有行为数据，默认最低风险

        scores = {}

        # 1. 评估登录时间异常性
        if 'login_time' in self.current_session_behavior:
            login_hour = self.current_session_behavior['login_time']
            if self.user_profile['login_times']:
                # 检查当前登录时间是否在用户常用时间范围内
                time_deviation = min(abs(login_hour - h) for h in self.user_profile['login_times'])
                if time_deviation <= 1:  # 1小时内的偏差
                    scores['login_time'] = 1.0
                elif time_deviation <= 3:  # 3小时内的偏差
                    scores['login_time'] = 0.7
                else:  # 大偏差
                    scores['login_time'] = 0.3
            else:
                scores['login_time'] = 0.5  # 没有历史数据

        # 2. 评估浏览器指纹匹配度
        if 'browser' in self.current_session_behavior:
            browser = self.current_session_behavior['browser']
            if browser in self.user_profile['browsers']:
                scores['browser_fingerprint'] = 1.0
            else:
                scores['browser_fingerprint'] = 0.3

        # 3. 评估IP地址匹配度
        if 'ip_address' in self.current_session_behavior:
            ip = self.current_session_behavior['ip_address']
            if ip in self.user_profile['ip_addresses']:
                scores['ip_location'] = 1.0
            else:
                scores['ip_location'] = 0.4

        # 4. 评估交易行为模式
        if 'transactions' in self.current_session_behavior:
            tx_score = 1.0
            transactions = self.current_session_behavior['transactions']

            if transactions:
                # 检查交易金额是否偏离平均值
                avg_amount = self.user_profile['transaction_patterns']['avg_amount']
                if avg_amount > 0:
                    for tx in transactions:
                        amount = tx['amount']
                        if amount > avg_amount * 3:  # 金额异常高
                            tx_score *= 0.5

                # 检查收款人是否常用
                common_recipients = self.user_profile['transaction_patterns']['common_recipients']
                for tx in transactions:
                    dest = str(tx.get('destination'))
                    if dest and dest not in common_recipients:
                        tx_score *= 0.8

                scores['transaction_pattern'] = max(0.2, tx_score)  # 下限0.2
            else:
                scores['transaction_pattern'] = 0.8

        # 计算加权风险分数
        final_score = 0
        total_weight = 0

        for feature, weight in FEATURE_WEIGHTS.items():
            if feature in scores:
                final_score += scores[feature] * weight
                total_weight += weight

        if total_weight > 0:
            final_score /= total_weight
        else:
            final_score = 0.5  # 默认中等风险

        self.current_risk_score = final_score

        # 记录异常行为
        if final_score < HIGH_RISK_THRESHOLD:
            log_security_event(
                self.user_id,
                "high_risk_behavior_detected",
                f"Unusual user behavior detected, risk score: {final_score:.2f}"
            )

        return final_score

    def get_verification_level(self) -> str:
        """根据风险分数确定验证级别"""
        score = self.calculate_risk_score()

        if score >= LOW_RISK_THRESHOLD:
            return "low"  # 低风险，可能不需要额外验证
        elif score >= HIGH_RISK_THRESHOLD:
            return "medium"  # 中等风险，可能需要简单的额外验证
        else:
            return "high"  # 高风险，需要严格的额外验证

    def _save_profile(self) -> None:
        """保存用户行为配置文件"""
        session = Session()
        try:
            user = session.query(Users).filter_by(user_id=self.user_id).first()
            if user:
                if not hasattr(user, 'behavioral_profile'):
                    # 我们需要确保数据库中有此字段
                    pass
                else:
                    user.behavioral_profile = json.dumps(self.user_profile)
                    session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error saving behavioral profile: {str(e)}")
        finally:
            session.close()


# 全局行为分析器实例缓存
_behavior_profilers = {}


def get_behavior_profiler(user_id: int) -> BehavioralProfiler:
    """获取或创建用户行为分析器"""
    if user_id not in _behavior_profilers:
        _behavior_profilers[user_id] = BehavioralProfiler(user_id)
    return _behavior_profilers[user_id]


def update_login_behavior(user_id: int, ip_address: str, user_agent: str) -> None:
    """登录时更新用户行为数据"""
    profiler = get_behavior_profiler(user_id)
    profiler.update_login_behavior(
        ip_address,
        user_agent,
        datetime.datetime.now()
    )


def update_transaction_behavior(user_id: int, transaction_data: Dict) -> None:
    """交易时更新用户行为数据"""
    profiler = get_behavior_profiler(user_id)
    profiler.update_transaction_behavior(transaction_data)


def get_risk_level(user_id: int) -> str:
    """获取当前用户的风险级别"""
    profiler = get_behavior_profiler(user_id)
    return profiler.get_verification_level()


def should_require_verification(user_id: int, transaction_data: Dict) -> bool:
    """根据风险级别确定是否需要额外验证"""
    # 首先基于交易本身的特征判断
    from security.integrity import is_high_risk_transaction
    if is_high_risk_transaction(transaction_data):
        return True

    # 然后基于用户行为风险判断
    risk_level = get_risk_level(user_id)
    if risk_level == "high":
        return True
    elif risk_level == "medium":
        # 中等风险，根据交易金额进行判断
        amount = float(transaction_data.get('amount', 0))
        profiler = get_behavior_profiler(user_id)
        avg_amount = profiler.user_profile['transaction_patterns']['avg_amount']
        if amount > avg_amount * 1.5:  # 交易金额显著高于平均值
            return True

    # 低风险或其他情况，不需要额外验证
    return False