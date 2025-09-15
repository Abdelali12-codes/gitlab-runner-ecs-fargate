#!/usr/bin/env python3
"""
GitLab Runner on ECS Fargate - AWS CDK Implementation
Based on official GitLab documentation and AWS best practices
"""

import os
from typing import Dict, List, Optional
from aws_cdk import (
    App,
    Stack,
    StackProps,
    Environment,
    SecretValue,
    CfnOutput,
    Duration,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecr as ecr,
    aws_iam as iam,
    aws_logs as logs,
    aws_secretsmanager as secretsmanager,
    aws_s3 as s3,
    aws_autoscaling as autoscaling,
    aws_elasticloadbalancingv2 as elbv2,
)
from constructs import Construct
from aws_cdk.aws_ecr_assets import DockerImageAsset


class GitLabRunnerConfig:
    """Configuration class for GitLab Runner deployment"""
    
    def __init__(self):
        self.app_name = "gitlab-runner"
        self.gitlab_url = "https://gitlab.com/"
        self.gitlab_runner_version = "16.5.0"  # Latest stable version
        self.concurrent_jobs = 10
        self.runner_tags = ["aws", "fargate", "docker"]
        self.enable_public_ip = False  # Security best practice
        self.ssh_port = 22
        self.ssh_username = "root"
        
        # Task definition settings
        self.task_cpu = 1024  # 1 vCPU
        self.task_memory = 2048  # 2 GB
        self.desired_count = 1
        
        # Environment
        self.environment = Environment(
            region="us-east-2",
            account="080266302756"
        )


class GitLabRunnerFargateStack(Stack):
    """Main stack for GitLab Runner on ECS Fargate"""

    def __init__(self, scope: Construct, construct_id: str, config: GitLabRunnerConfig, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.config = config
        
        # Create VPC or use existing
        self.vpc = self._create_or_get_vpc()
        
        # Create security groups
        self.runner_sg, self.task_sg = self._create_security_groups()
        
        # Create GitLab token secret
        self.gitlab_secret = self._create_gitlab_secret()
        
        # Create S3 bucket for cache and artifacts
        self.cache_bucket = self._create_cache_bucket()
        
        # Create ECR repository for runner images
        self.ecr_repo = self._create_ecr_repository()
        
        # Create ECS cluster
        self.cluster = self._create_ecs_cluster()
        
        # Create IAM roles
        self.task_role, self.execution_role = self._create_iam_roles()
        
        # Create task definition for CI coordinator
        self.task_definition = self._create_task_definition()
        
        # Create runner manager EC2 instance
        self.runner_instance = self._create_runner_manager()
        
        # Create outputs
        self._create_outputs()

    def _create_or_get_vpc(self) -> ec2.Vpc:
        """Create VPC with public and private subnets"""
        
        # Check if VPC ID is provided via context
        vpc_id = self.node.try_get_context("vpcId")
        
        if vpc_id:
            return ec2.Vpc.from_lookup(self, "ExistingVpc", vpc_id=vpc_id)
        
        # Create new VPC with NAT Gateways
        return ec2.Vpc(
            self, 
            "GitLabRunnerVpc",
            max_azs=2,
            nat_gateways=1,  # Cost optimization
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="PublicSubnet",
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    name="PrivateSubnet", 
                    cidr_mask=24
                )
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True
        )

    def _create_security_groups(self) -> tuple[ec2.SecurityGroup, ec2.SecurityGroup]:
        """Create security groups for runner manager and Fargate tasks"""
        
        # Security group for runner manager EC2
        runner_sg = ec2.SecurityGroup(
            self,
            "RunnerManagerSG",
            vpc=self.vpc,
            description="Security group for GitLab Runner manager",
            allow_all_outbound=True
        )
        
        # Allow SSH from specific CIDR (customize as needed)
        runner_sg.add_ingress_rule(
            ec2.Peer.ipv4("0.0.0.0/0"),  # Restrict this in production
            ec2.Port.tcp(22),
            "SSH access"
        )
        
        # Security group for Fargate tasks
        task_sg = ec2.SecurityGroup(
            self,
            "FargateTaskSG", 
            vpc=self.vpc,
            description="Security group for Fargate CI tasks",
            allow_all_outbound=True
        )
        
        # Allow SSH from runner manager
        task_sg.add_ingress_rule(
            runner_sg,
            ec2.Port.tcp(self.config.ssh_port),
            "SSH from runner manager"
        )
        
        return runner_sg, task_sg

    def _create_gitlab_secret(self) -> secretsmanager.Secret:
        """Create GitLab runner registration token secret"""
        gitlab_token = self.node.try_get_context("gitlab_token")
        return secretsmanager.Secret(
            self,
            "GitLabRunnerSecret",
            description="GitLab Runner registration token",
            secret_object_value={
                "token": SecretValue.unsafe_plain_text(gitlab_token),
                "url": SecretValue.unsafe_plain_text(self.config.gitlab_url)
            },
            removal_policy=RemovalPolicy.DESTROY
        )

    def _create_cache_bucket(self) -> s3.Bucket:
        """Create S3 bucket for GitLab Runner cache and artifacts"""
        
        return s3.Bucket(
            self,
            "GitLabRunnerCache",
            bucket_name=f"{self.config.app_name}-cache-{self.account}",
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DeleteOldVersions",
                    abort_incomplete_multipart_upload_after=Duration.days(1),
                    noncurrent_version_expiration=Duration.days(7)
                )
            ],
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )

    def _create_ecr_repository(self) -> ecr.Repository:
        """Create ECR repository for custom runner images"""

        # gitlab_runner = DockerImageAsset(
        #         self,
        #         "GitlabRunnerImage",
        #         directory="./gitlab_ci_fargate_runner/docker_fargate_driver",
        #         build_args={
        #             "GITLAB_RUNNER_VERSION": props.get("gitlab_runner_version")
        #         }
        #     )
        
        return ecr.Repository(
            self,
            "GitLabRunnerECR",
            repository_name=f"{self.config.app_name}-images",
            lifecycle_rules=[
                ecr.LifecycleRule(
                    max_image_count=10,
                    tag_status=ecr.TagStatus.UNTAGGED
                )
            ],
            removal_policy=RemovalPolicy.DESTROY
        )

    def _create_ecs_cluster(self) -> ecs.Cluster:
        """Create ECS cluster with Fargate capacity provider"""
        
        cluster = ecs.Cluster(
            self,
            "GitLabRunnerCluster",
            cluster_name=f"{self.config.app_name}-cluster",
            vpc=self.vpc,
            enable_fargate_capacity_providers=True
        )
        
        # Add CloudWatch container insights
        cluster.add_default_cloud_map_namespace(
            name=f"{self.config.app_name}.local"
        )
        
        return cluster

    def _create_iam_roles(self) -> tuple[iam.Role, iam.Role]:
        """Create IAM roles for ECS task and execution"""
        
        # Task role - permissions for the running container
        task_role = iam.Role(
            self,
            "GitLabRunnerTaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="Role for GitLab Runner Fargate tasks"
        )
        
        # Add permissions for S3 cache access
        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:PutObject", 
                    "s3:DeleteObject"
                ],
                resources=[f"{self.cache_bucket.bucket_arn}/*"]
            )
        )
        
        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["s3:ListBucket"],
                resources=[self.cache_bucket.bucket_arn]
            )
        )
        
        # Add permissions for ECS task metadata
        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ecs:DescribeTasks",
                    "ecs:DescribeTaskDefinition"
                ],
                resources=["*"]
            )
        )
        
        # Execution role - permissions to start the container
        execution_role = iam.Role(
            self,
            "GitLabRunnerExecutionRole", 
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonECSTaskExecutionRolePolicy")
            ]
        )
        
        # Add permissions to pull from ECR
        execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability", 
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage"
                ],
                resources=["*"]
            )
        )
        
        # Add permissions to read secrets
        execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[self.gitlab_secret.secret_arn]
            )
        )
        
        return task_role, execution_role

    def _create_task_definition(self) -> ecs.TaskDefinition:
        """Create ECS task definition for CI coordinator"""
        
        task_def = ecs.FargateTaskDefinition(
            self,
            "GitLabRunnerTaskDef",
            family=f"{self.config.app_name}-ci-coordinator",
            cpu=self.config.task_cpu,
            memory_limit_mib=self.config.task_memory,
            task_role=self.task_role,
            execution_role=self.execution_role
        )
        
        # Create CloudWatch log group
        log_group = logs.LogGroup(
            self,
            "GitLabRunnerLogs",
            log_group_name=f"/aws/ecs/{self.config.app_name}",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # Add ci-coordinator container (required name for Fargate driver)
        container = task_def.add_container(
            "ci-coordinator",  # Required name for GitLab Fargate driver
            image=ecs.ContainerImage.from_registry("ubuntu:22.04"),  # Base image
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="gitlab-runner",
                log_group=log_group
            ),
            environment={
                "GITLAB_URL": self.config.gitlab_url,
                "RUNNER_TAGS": ",".join(self.config.runner_tags)
            }
        )
        
        # Add port mapping for SSH
        container.add_port_mappings(
            ecs.PortMapping(
                container_port=self.config.ssh_port,
                protocol=ecs.Protocol.TCP
            )
        )
        
        return task_def

    def _create_runner_manager(self) -> ec2.Instance:
        """Create EC2 instance to host GitLab Runner manager"""
        
        # Create IAM role for runner manager
        runner_role = iam.Role(
            self,
            "RunnerManagerRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        
        # Add ECS permissions
        runner_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECS_FullAccess")
        )
        
        # Add permissions to read GitLab secret
        runner_role.add_to_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[self.gitlab_secret.secret_arn]
            )
        )
        
        # Create key pair (optional - use existing or create manually)
        key_pair = ec2.CfnKeyPair(
            self,
            "GitLabRunnerKeyPair",
            key_name=f"{self.config.app_name}-keypair"
        )
        
        # User data script to install and configure GitLab Runner
        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "apt-get update -y",
            "apt-get install -y curl software-properties-common",
            
            # Install GitLab Runner
            'curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | bash',
            "apt-get install gitlab-runner -y",
            
            # Create directories
            "mkdir -p /opt/gitlab-runner/{metadata,builds,cache}",
            "chown gitlab-runner:gitlab-runner /opt/gitlab-runner/{metadata,builds,cache}",
            
            # Download Fargate driver
            'curl -Lo /opt/gitlab-runner/fargate "https://gitlab-runner-custom-fargate-downloads.s3.amazonaws.com/latest/fargate-linux-amd64"',
            "chmod +x /opt/gitlab-runner/fargate",
            
            # Install AWS CLI
            "curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip",
            "apt-get install -y unzip",
            "unzip awscliv2.zip",
            "./aws/install",
            
            # Get GitLab token from Secrets Manager
            f'GITLAB_TOKEN=$(aws secretsmanager get-secret-value --secret-id {self.gitlab_secret.secret_name} --region {self.region} --query SecretString --output text | python3 -c "import sys, json; print(json.load(sys.stdin)[\'token\'])")',
            
            # Register runner
            f'gitlab-runner register --non-interactive --url "{self.config.gitlab_url}" --token "$GITLAB_TOKEN" --name "fargate-runner" --executor custom',
            
            # Create Fargate configuration
            f"""cat > /etc/gitlab-runner/fargate.toml << 'EOF'
LogLevel = "info"
LogFormat = "text"

[Fargate]
Cluster = "{self.cluster.cluster_name}"
Region = "{self.region}"
Subnet = "{self.vpc.private_subnets[0].subnet_id}"
SecurityGroup = "{self.task_sg.security_group_id}"
TaskDefinition = "{self.task_definition.family}:1"
EnablePublicIP = {str(self.config.enable_public_ip).lower()}

[TaskMetadata]
Directory = "/opt/gitlab-runner/metadata"

[SSH]
Username = "{self.config.ssh_username}"
Port = {self.config.ssh_port}
EOF""",
            
            # Update GitLab Runner config
            f"""cat > /etc/gitlab-runner/config.toml << 'EOF'
concurrent = {self.config.concurrent_jobs}
check_interval = 0

[session_server]
  session_timeout = 1800

[[runners]]
  name = "fargate-runner"
  token = "$GITLAB_TOKEN"
  url = "{self.config.gitlab_url}"
  executor = "custom"
  builds_dir = "/opt/gitlab-runner/builds"
  cache_dir = "/opt/gitlab-runner/cache"
  [runners.custom]
    config_exec = "/opt/gitlab-runner/fargate"
    config_args = ["--config", "/etc/gitlab-runner/fargate.toml", "custom", "config"]
    prepare_exec = "/opt/gitlab-runner/fargate" 
    prepare_args = ["--config", "/etc/gitlab-runner/fargate.toml", "custom", "prepare"]
    run_exec = "/opt/gitlab-runner/fargate"
    run_args = ["--config", "/etc/gitlab-runner/fargate.toml", "custom", "run"]
    cleanup_exec = "/opt/gitlab-runner/fargate"
    cleanup_args = ["--config", "/etc/gitlab-runner/fargate.toml", "custom", "cleanup"]
  [runners.cache]
    Type = "s3"
    [runners.cache.s3]
      ServerAddress = "s3.{self.region}.amazonaws.com"
      BucketName = "{self.cache_bucket.bucket_name}"
      BucketLocation = "{self.region}"
EOF""",
            
            # Restart GitLab Runner
            "systemctl restart gitlab-runner",
            "systemctl enable gitlab-runner"
        )
        
        # ✅ Ubuntu 22.04 AMI from SSM (works across all regions)
        ubuntu_ami = ec2.MachineImage.from_ssm_parameter(
            parameter_name="/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
        )

        # Create runner manager instance
        instance = ec2.Instance(
            self,
            "RunnerManagerInstance",
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
            machine_image=ubuntu_ami,
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            security_group=self.runner_sg,
            role=runner_role,
            user_data=user_data,
            key_name=key_pair.key_name
        )
        
        return instance

    def _create_outputs(self) -> None:
        """Create CloudFormation outputs"""
        
        CfnOutput(
            self,
            "ClusterName",
            value=self.cluster.cluster_name,
            description="ECS Cluster name"
        )
        
        CfnOutput(
            self,
            "TaskDefinitionArn",
            value=self.task_definition.task_definition_arn,
            description="Task definition ARN"
        )
        
        CfnOutput(
            self,
            "ECRRepositoryUri",
            value=self.ecr_repo.repository_uri,
            description="ECR repository URI"
        )
        
        CfnOutput(
            self,
            "CacheBucketName",
            value=self.cache_bucket.bucket_name,
            description="S3 cache bucket name"
        )
        
        CfnOutput(
            self,
            "RunnerInstanceId",
            value=self.runner_instance.instance_id,
            description="Runner manager instance ID"
        )
        
        CfnOutput(
            self,
            "GitLabSecretName",
            value=self.gitlab_secret.secret_name,
            description="GitLab token secret name"
        )


# CDK App
def main():
    app = App()
    
    # Load configuration
    config = GitLabRunnerConfig()
    
    # Create main stack
    GitLabRunnerFargateStack(
        app,
        "GitLabRunnerFargateStack",
        config=config,
        env=config.environment,
        description="GitLab Runner on ECS Fargate with custom executor"
    )
    
    app.synth()


if __name__ == "__main__":
    main()