import time
import json
import hashlib
import datetime
from typing import Dict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from config.mybank_db import Users
from security.audit import log_security_event

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

FEATURE_WEIGHTS = {
    'login_time': 0.2,  # Login time anomaly
    'browser_fingerprint': 0.25,  # Browser fingerprint match
    'ip_location': 0.25,  # IP address location match
    'typing_pattern': 0.15,  # Keystroke pattern match
    'transaction_pattern': 0.15  # Transaction behavior pattern match
}

# Risk thresholds
LOW_RISK_THRESHOLD = 0.7  # Scores above this value are considered low risk
HIGH_RISK_THRESHOLD = 0.4  # Scores below this value are considered high risk

class BehavioralProfiler:
    """User behavior analyzer for continuous authentication"""

    def __init__(self, user_id: int):
        self.user_id = user_id
        self.user_profile = self._load_user_profile()
        self.current_session_behavior = {}
        self.current_risk_score = 1.0  # Initial risk score (maximum is 1, lowest risk)

    def _load_user_profile(self) -> Dict:
        """Load the user's behavioral profile baseline"""
        session = Session()
        try:
            user = session.query(Users).filter_by(user_id=self.user_id).first()
            if not user:
                return self._create_default_profile()

            # Attempt to load existing profile
            try:
                if hasattr(user, 'behavioral_profile') and user.behavioral_profile:
                    return json.loads(user.behavioral_profile)
            except:
                pass

            # If no profile exists, create a default one
            return self._create_default_profile()
        finally:
            session.close()

    def _create_default_profile(self) -> Dict:
        """Create a default user behavioral profile"""
        current_time = time.time()
        return {
            'login_times': [],  # Stores the last 10 login times
            'ip_addresses': [],  # Recently used IP addresses
            'browsers': [],  # Recently used browsers
            'typing_patterns': [],  # Keystroke rhythm patterns
            'transaction_patterns': {  # Transaction behavior patterns
                'avg_amount': 0,
                'common_recipients': [],
                'frequency': {}
            },
            'last_updated': current_time,
            'creation_time': current_time,
            'login_count': 0
        }

    def update_login_behavior(self, ip_address: str, user_agent: str, login_time: datetime.datetime) -> None:
        """Update login behavior data"""
        profile = self.user_profile

        # Update login times
        profile['login_times'].append(login_time.hour)
        if len(profile['login_times']) > 10:
            profile['login_times'] = profile['login_times'][-10:]

        # Update IP addresses
        if ip_address not in profile['ip_addresses']:
            profile['ip_addresses'].append(ip_address)
            if len(profile['ip_addresses']) > 5:
                profile['ip_addresses'] = profile['ip_addresses'][-5:]

        # Update browser information
        browser_hash = hashlib.md5(user_agent.encode()).hexdigest()
        if browser_hash not in profile['browsers']:
            profile['browsers'].append(browser_hash)
            if len(profile['browsers']) > 3:
                profile['browsers'] = profile['browsers'][-3:]

        # Update login count
        profile['login_count'] += 1
        profile['last_updated'] = time.time()

        # Save the updated profile
        self._save_profile()

        # Update current session behavior data
        self.current_session_behavior['login_time'] = login_time.hour
        self.current_session_behavior['ip_address'] = ip_address
        self.current_session_behavior['browser'] = browser_hash

    def update_transaction_behavior(self, transaction_data: Dict) -> None:
        """Update trading behavior data"""
        profile = self.user_profile
        patterns = profile['transaction_patterns']

        # Update the average transaction amount
        amount = float(transaction_data.get('amount', 0))
        if patterns['avg_amount'] == 0:
            patterns['avg_amount'] = amount
        else:
            patterns['avg_amount'] = (patterns['avg_amount'] * 0.9) + (amount * 0.1)

        # Update regular payees
        if 'destination_account_id' in transaction_data:
            dest = str(transaction_data['destination_account_id'])
            if dest not in patterns['common_recipients']:
                patterns['common_recipients'].append(dest)
                if len(patterns['common_recipients']) > 10:
                    patterns['common_recipients'] = patterns['common_recipients'][-10:]

        # Update trading frequency
        hour = datetime.datetime.now().hour
        hour_key = str(hour)
        if hour_key in patterns['frequency']:
            patterns['frequency'][hour_key] += 1
        else:
            patterns['frequency'][hour_key] = 1

        profile['last_updated'] = time.time()
        self._save_profile()

        # Update the behavior data of the current session
        current_tx = self.current_session_behavior.get('transactions', [])
        current_tx.append({
            'amount': amount,
            'destination': transaction_data.get('destination_account_id'),
            'time': hour
        })
        self.current_session_behavior['transactions'] = current_tx

    def calculate_risk_score(self) -> float:
        """Calculate the risk score for the current session"""
        if not self.current_session_behavior:
            return 1.0  # No behavior data, default lowest risk

        scores = {}

        # 1. Evaluate login time abnormality
        if 'login_time' in self.current_session_behavior:
            login_hour = self.current_session_behavior['login_time']
            if self.user_profile['login_times']:
                # Check if current login time is within user's normal time range
                time_deviation = min(abs(login_hour - h) for h in self.user_profile['login_times'])
                if time_deviation <= 1:  # Deviation within 1 hour
                    scores['login_time'] = 1.0
                elif time_deviation <= 3:  # Deviation within 3 hours
                    scores['login_time'] = 0.7
                else:  # Large deviation
                    scores['login_time'] = 0.3
            else:
                scores['login_time'] = 0.5  # No historical data

        # 2. Evaluate browser fingerprint match
        if 'browser' in self.current_session_behavior:
            browser = self.current_session_behavior['browser']
            if browser in self.user_profile['browsers']:
                scores['browser_fingerprint'] = 1.0
            else:
                scores['browser_fingerprint'] = 0.3

        # 3. Evaluate IP address match
        if 'ip_address' in self.current_session_behavior:
            ip = self.current_session_behavior['ip_address']
            if ip in self.user_profile['ip_addresses']:
                scores['ip_location'] = 1.0
            else:
                scores['ip_location'] = 0.4

        # 4. Evaluate transaction behavior patterns
        if 'transactions' in self.current_session_behavior:
            tx_score = 1.0
            transactions = self.current_session_behavior['transactions']

            if transactions:
                avg_amount = self.user_profile['transaction_patterns']['avg_amount']
                if avg_amount > 0:
                    for tx in transactions:
                        amount = tx['amount']
                        if amount > avg_amount * 3:  # Abnormally high amount
                            tx_score *= 0.5
                common_recipients = self.user_profile['transaction_patterns']['common_recipients']
                for tx in transactions:
                    dest = str(tx.get('destination'))
                    if dest and dest not in common_recipients:
                        tx_score *= 0.8

                scores['transaction_pattern'] = max(0.2, tx_score)  # Lower limit 0.2
            else:
                scores['transaction_pattern'] = 0.8

        final_score = 0
        total_weight = 0

        for feature, weight in FEATURE_WEIGHTS.items():
            if feature in scores:
                final_score += scores[feature] * weight
                total_weight += weight

        if total_weight > 0:
            final_score /= total_weight
        else:
            final_score = 0.5

        self.current_risk_score = final_score

        if final_score < HIGH_RISK_THRESHOLD:
            log_security_event(
                self.user_id,
                "high_risk_behavior_detected",
                f"Unusual user behavior detected, risk score: {final_score:.2f}"
            )

        return final_score

    def get_verification_level(self) -> str:
        """Determine the level of validation based on the risk score"""
        score = self.calculate_risk_score()

        if score >= LOW_RISK_THRESHOLD:
            return "low"
        elif score >= HIGH_RISK_THRESHOLD:
            return "medium"
        else:
            return "high"

    def _save_profile(self) -> None:
        """Save the user behavior profile"""
        session = Session()
        try:
            user = session.query(Users).filter_by(user_id=self.user_id).first()
            if user:
                if not hasattr(user, 'behavioral_profile'):
                    pass
                else:
                    user.behavioral_profile = json.dumps(self.user_profile)
                    session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error saving behavioral profile: {str(e)}")
        finally:
            session.close()


# Global behavior analyzer instance cache
_behavior_profilers = {}


def get_behavior_profiler(user_id: int) -> BehavioralProfiler:
    """Gets or creates a user behavior analyzer"""
    if user_id not in _behavior_profilers:
        _behavior_profilers[user_id] = BehavioralProfiler(user_id)
    return _behavior_profilers[user_id]


def update_login_behavior(user_id: int, ip_address: str, user_agent: str) -> None:
    """Update user behavior data at login"""
    profiler = get_behavior_profiler(user_id)
    profiler.update_login_behavior(
        ip_address,
        user_agent,
        datetime.datetime.now()
    )


def update_transaction_behavior(user_id: int, transaction_data: Dict) -> None:
    """Update user behavior data while trading"""
    profiler = get_behavior_profiler(user_id)
    profiler.update_transaction_behavior(transaction_data)


def get_risk_level(user_id: int) -> str:
    """Get the risk level of the current user"""
    profiler = get_behavior_profiler(user_id)
    return profiler.get_verification_level()


def should_require_verification(user_id: int, transaction_data: Dict) -> bool:
    """Determine if additional validation is required based on the level of risk"""
    # First of all, based on the characteristics of the transaction itself
    from security.integrity import is_high_risk_transaction
    if is_high_risk_transaction(transaction_data):
        return True

    # Then based on the user behavior risk judgment
    risk_level = get_risk_level(user_id)
    if risk_level == "high":
        return True
    elif risk_level == "medium":
        # Medium risk, judging by the amount of the transaction
        amount = float(transaction_data.get('amount', 0))
        profiler = get_behavior_profiler(user_id)
        avg_amount = profiler.user_profile['transaction_patterns']['avg_amount']
        if amount > avg_amount * 1.5:  # The transaction amount is significantly higher than the average
            return True

    # Low risk or otherwise, no additional verification is required
    return False

