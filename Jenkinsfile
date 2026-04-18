pipeline {
    agent any

    triggers {
        githubPush()
    }

    environment {
        REPORT_DIR = "reports"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                python3 -m pip install --upgrade pip --break-system-packages || true
                python3 -m pip install cryptography --break-system-packages
                '''
            }
        }

        stage('Verify Signature') {
            steps {
                script {
                    def result = sh(
                        script: 'python3 verify_sig.py output.sig trivy_report.json public_key.pem',
                        returnStatus: true
                    )

                    if (result != 0) {
                        error("❌ Signature is INVALID — build failed.")
                    }
                }
            }
        }

        stage('Pull Docker Image') {
            steps {
                sh 'docker pull pen-tool:latest || true'
            }
        }

        stage('Run Pentest Toolkit') {
            steps {
                sh '''
                mkdir -p $REPORT_DIR

                docker run -u root --rm \
                  -v "$WORKSPACE/$REPORT_DIR:/app" \
                  -w /app \
                  parthg23/pentest-toolkit:latest \
                  pentest.sh pen-tool:latest
                '''
            }
        }

        stage('Run Security Auditor') {
            steps {
                sh '''
                mkdir -p $REPORT_DIR

                docker run -u root --rm \
                  -v "$WORKSPACE/$REPORT_DIR:/app" \
                  -w /app \
                  parthg23/security-auditor:latest \
                  /audit/containertest.sh sec-aud:latest
                '''
            }
        }
    }

    post {
        success {
            echo "✅ Pipeline completed successfully."
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }

        failure {
            echo "❌ Pipeline failed."
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
    }
}