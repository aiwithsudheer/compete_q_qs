import boto3
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_quicksight_user(aws_account_id, namespace, email, iam_role_arn, user_name=None):
    """
    Create a QuickSight user with an IAM role
    
    Args:
        aws_account_id (str): AWS account ID
        namespace (str): QuickSight namespace (default is 'default')
        email (str): Email address of the user
        iam_role_arn (str): ARN of the IAM role to assign to the user
        user_name (str, optional): Custom username. If not provided, email will be used
    
    Returns:
        dict: Response from QuickSight API
    """
    # Initialize QuickSight client
    quicksight = boto3.client('quicksight', region_name=os.getenv('AWS_REGION'))
    
    # Use email as username if not provided
    if user_name is None:
        user_name = email
    
    try:
        response = quicksight.register_user(
            IdentityType='IAM',  # Using IAM authentication
            Email=email,
            UserRole='ADMIN',  # Can be 'ADMIN', 'AUTHOR', 'READER', or 'RESTRICTED_AUTHOR'
            IamArn=iam_role_arn,
            SessionName=user_name,
            AwsAccountId=aws_account_id,
            Namespace=namespace
        )
        return response
    except Exception as e:
        print(f"Error creating QuickSight user: {str(e)}")
        raise

if __name__ == "__main__":
    # Example usage
    aws_account_id = os.getenv('AWS_ACCOUNT_ID')
    iam_role_arn = os.getenv('IAM_ROLE_ARN')
    email = os.getenv('QUICKSIGHT_USER_EMAIL')
    
    if not all([aws_account_id, iam_role_arn, email]):
        print("Please set the following environment variables:")
        print("AWS_ACCOUNT_ID, IAM_ROLE_ARN, QUICKSIGHT_USER_EMAIL")
        exit(1)
    
    try:
        response = create_quicksight_user(
            aws_account_id=aws_account_id,
            namespace='default',
            email=email,
            iam_role_arn=iam_role_arn
        )
        print("QuickSight user created successfully!")
        print(f"User ARN: {response['User']['Arn']}")
    except Exception as e:
        print(f"Failed to create QuickSight user: {str(e)}") 