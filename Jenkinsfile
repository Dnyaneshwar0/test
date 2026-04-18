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
        IMAGES_TO_SCAN = "nginx:latest redis:alpin"
        CONTAINERS_TO_SCAN = "my-nginx my-nginx-2"
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
                script {
                    def images = env.IMAGES_TO_SCAN.split()
                    images.each { image ->
                        sh """
                            echo "Scanning image: ${image}"
                            docker run -u root --rm \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v "\$(pwd)/../reports:/workspace" \
                                pentest-toolkit:latest \
                                pentest.sh ${image}
                        """
                    }
                }            
            }
        }


        // =========================
        // SECURITY AUDITOR (CONTAINER SCAN)
        // =========================
        stage('Security Auditor - Container Scan') {
            steps {
            script {
                    def containers = env.CONTAINERS_TO_SCAN.split()
                    containers.each { cname ->
                        sh """
                            echo "Scanning container: ${cname}"
                            docker run -u root --rm \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v "\$(pwd)/../reports:/workspace" \
                                security-auditor:latest \
                                /audit/containertest.sh ${cname}
                        """
                    }
                }
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


