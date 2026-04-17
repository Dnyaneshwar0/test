pipeline {
    agent any

    triggers {
        githubPush()
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh 'pip install cryptography --quiet --break-system-packages || pip install cryptography --quiet'
            }
        }

        stage('Verify Signature') {
            steps {
                script {
                    def result = sh(
                        script: 'python3 verify_sig.py output.sig sbom.json public_key.pem',
                        returnStatus: true
                    )

                    if (result != 0) {
                        error("❌ Signature is INVALID — build failed.")
                    }
                }
            }
        }
    }

    post {
        success {
            echo "✅ Signature is VALID."
        }
        failure {
            echo "❌ Signature is INVALID."
        }
    }
}
