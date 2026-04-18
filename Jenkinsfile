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
                sh '''
                pip install cryptography --quiet --break-system-packages || pip install cryptography --quiet
                '''
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

        stage('Run Pentest Toolkit') {
            steps {
                sh '''
                mkdir -p reports

                docker run -u root --rm \
                  -v /var/run/docker.sock:/var/run/docker.sock \
                  -v "$WORKSPACE/reports":/app \
                  -w /app \
                  parthg23/pentest-toolkit:latest \
                  pentest.sh pen-tool:latest
                '''
            }
        }

        stage('Run Security Auditor') {
            steps {
                sh '''
                mkdir -p reports

                docker run -u root --rm \
                  -v /var/run/docker.sock:/var/run/docker.sock \
                  -v "$WORKSPACE/reports":/app \
                  -w /app \
                  parthg23/security-auditor:latest \
                  /audit/containertest.sh sec-aud:latest
                '''
            }
        }
    }

    post {
        success {
            echo "✅ Signature VALID + Security scans completed."
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }

        failure {
            echo "❌ Pipeline failed (signature or security scan)."
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
    }
}