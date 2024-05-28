from channels.generic.websocket import WebsocketConsumer
import json
import joblib
import requests

class RealTimeAnalysisConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()

    def receive(self, text_data):
        data = json.loads(text_data)
        processed_data = self.process_data(data)
        self.send(text_data=json.dumps({
            'message': 'Processed data',
            'data': processed_data
        }))

    def process_data(self, data):
        incident_type = data.get('incident_type')
        details = data.get('details', {})

        if incident_type == 'malware_detection':
            file_hash = details.get('file_hash')
            if file_hash:
                return self.handle_malware_detection(file_hash)

        elif incident_type == 'phishing_attempt':
            email_text = details.get('email_text')
            if email_text:
                return self.handle_phishing_attempt(email_text)

        elif incident_type == 'suspicious_activity':
            network_data = details.get('network_data')
            if network_data:
                return self.handle_suspicious_activity(network_data)

        return {'status': 'unknown incident type'}

    def handle_malware_detection(self, file_hash):
        vt_response = self.lookup_virus_total(file_hash)
        if vt_response['positives'] > 0:
            self.alert_security_team(f"Malware detected with hash: {file_hash}")
            return {'status': 'malware detected', 'details': vt_response}
        return {'status': 'no malware detected'}

    def handle_phishing_attempt(self, email_text):
        if self.detect_phishing(email_text):
            self.alert_security_team(f"Phishing attempt detected in email: {email_text}")
            return {'status': 'phishing detected'}
        return {'status': 'no phishing detected'}

    def handle_suspicious_activity(self, network_data):
        if self.detect_suspicious_activity(network_data):
            self.alert_security_team(f"Suspicious network activity detected: {network_data}")
            return {'status': 'suspicious activity detected'}
        return {'status': 'no suspicious activity detected'}

    def lookup_virus_total(self, file_hash):
        api_key = 'YOUR_VIRUSTOTAL_API_KEY'
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        return response.json()

    def alert_security_team(self, message):
        send_mail(
            'Security Alert',
            message,
            'from@example.com',
            ['security@example.com'],
            fail_silently=False,
        )

    def detect_phishing(self, email_text):
        vectorizer = joblib.load('vectorizer.pkl')
        model = joblib.load('phishing_model.pkl')
        X = vectorizer.transform([email_text])
        prediction = model.predict(X)
        return bool(prediction[0])

    def detect_suspicious_activity(self, network_data):
        model = joblib.load('anomaly_detection_model.pkl')
        predictions = model.predict([network_data])
        return predictions[0] == -1
