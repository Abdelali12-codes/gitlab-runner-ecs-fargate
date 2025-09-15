#!/usr/bin/env python3
import os

import aws_cdk as cdk

from ecs_fargate_gitlab_runner.ecs_fargate_gitlab_runner_stack import (GitLabRunnerConfig, GitLabRunnerFargateStack)

app = cdk.App()
config = GitLabRunnerConfig()
#Create main stack
GitLabRunnerFargateStack(
        app,
        "GitLabRunnerFargateStack",
        config=config,
        env=config.environment,
        description="GitLab Runner on ECS Fargate with custom executor"
    )
    
app.synth()
