import aws_cdk as core
import aws_cdk.assertions as assertions

from ecs_fargate_gitlab_runner.ecs_fargate_gitlab_runner_stack import EcsFargateGitlabRunnerStack

# example tests. To run these tests, uncomment this file along with the example
# resource in ecs_fargate_gitlab_runner/ecs_fargate_gitlab_runner_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = EcsFargateGitlabRunnerStack(app, "ecs-fargate-gitlab-runner")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
