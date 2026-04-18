pipeline {
    agent any


    // =========================
    // TRIGGERS
    // =========================
    triggers {
        githubPush()
    }


    // =========================
    // GLOBAL ENV VARIABLES
    // =========================
    environment {
        REPORT_DIR = "reports"
        IMAGE_TO_SCAN = "nginx:latest"
        CONTAINER_TO_SCAN = "my-nginx"
    }


    stages {


        // =========================
        // CHECKOUT CODE
        // =========================
        stage('Checkout') {
            steps {
                checkout scm
            }
        }


        // =========================
        // PYTHON ENV SETUP (CLEAN WAY)
        // =========================
        stage('Setup Python Environment') {
            steps {
                sh '''
                pip install cryptography --quiet --break-system-packages || pip install cryptography --quiet
                '''
            }
        }


        // =========================
        // SIGNATURE VERIFICATION
        // =========================
        stage('Verify Signature') {
            steps {
                script {
                    def result = sh(
                        script: '''
                        python3 verify_sig.py output.sig trivy_report.json public_key.pem
                        ''',
                        returnStatus: true
                    )


                    if (result != 0) {
                        error("❌ Signature INVALID — stopping pipeline.")
                    }
                }
            }
        }


        // =========================
        // PREPARE REPORT DIR
        // =========================
        stage('Prepare Reports') {
            steps {
                sh '''
                mkdir -p $REPORT_DIR
                '''
            }
        }


        // =========================
        // PENTEST TOOLKIT (IMAGE SCAN)
        // =========================
        stage('Pentest Toolkit - Image Scan') {
            steps {
                sh '''
                echo "Scanning image: $IMAGE_TO_SCAN"
                    sudo docker run -u root --rm \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    -v "$(pwd)/../reports:/reports" \
                    -w /app \
                    parthg23/pentest-toolkit:latest \
                    pentest.sh $IMAGE_TO_SCAN
                '''
            }
        }


        // =========================
        // SECURITY AUDITOR (CONTAINER SCAN)
        // =========================
        stage('Security Auditor - Container Scan') {
            steps {
                sh '''
                echo "Scanning container: $CONTAINER_TO_SCAN"

                sudo docker run -u root --rm \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v "$(pwd)/../reports":/app \
                -w /app \
                parthg23/security-auditor:latest \
                /audit/containertest.sh $CONTAINER_TO_SCAN

                '''
            }
        }
    }


    // =========================
    // POST ACTIONS
    // =========================
    post {
        success {
            echo "✅ Build SUCCESS — Signature verified + security scans completed."


            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }


        failure {
            echo "❌ Build FAILED — check logs (signature or security scan issue)."


            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
    }
}


