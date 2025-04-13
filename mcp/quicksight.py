import boto3
from typing import List, Dict, Any
import os
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load environment variables from .env file
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("quicksight")

def get_sts_credentials():
    """
    Assume a role using STS and return temporary credentials.
    
    Returns:
        Dictionary containing temporary credentials
    """
    sts_client = boto3.client(
        'sts',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )
    
    # Assume the role
    response = sts_client.assume_role(
        RoleArn=os.getenv('AWS_ROLE_ARN'),
        RoleSessionName='QuickSightSession'
    )
    
    # Return the temporary credentials
    return {
        'aws_access_key_id': response['Credentials']['AccessKeyId'],
        'aws_secret_access_key': response['Credentials']['SecretAccessKey'],
        'aws_session_token': response['Credentials']['SessionToken']
    }

def get_quicksight_client():
    """
    Create and return a QuickSight client with temporary credentials.
    
    Returns:
        boto3 QuickSight client
    """
    credentials = get_sts_credentials()
    return boto3.client(
        'quicksight',
        aws_access_key_id=credentials['aws_access_key_id'],
        aws_secret_access_key=credentials['aws_secret_access_key'],
        aws_session_token=credentials['aws_session_token'],
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )

@mcp.tool()
async def list_datasets() -> List[Dict[str, Any]]:
    """
    Get all datasets in QuickSight account.
    
    Returns:
        List of dataset information
    """
    client = get_quicksight_client()
    response = client.list_data_sets(AwsAccountId=boto3.client('sts').get_caller_identity()['Account'])
    return response.get('DataSetSummaries', [])

@mcp.tool()
async def list_data_sources() -> List[Dict[str, Any]]:
    """
    Get all data sources in QuickSight account.
    
    Returns:
        List of data source information
    """
    client = get_quicksight_client()
    response = client.list_data_sources(AwsAccountId=boto3.client('sts').get_caller_identity()['Account'])
    return response.get('DataSources', [])

@mcp.tool()
async def describe_dataset(dataset_id: str) -> Dict[str, Any]:
    """
    Describe a specific dataset in QuickSight.
    
    Args:
        dataset_id: ID of the dataset to describe
        
    Returns:
        Dataset description
    """
    client = get_quicksight_client()
    response = client.describe_data_set(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DataSetId=dataset_id
    )
    return response.get('DataSet', {})

@mcp.tool()
async def describe_data_source(data_source_id: str) -> Dict[str, Any]:
    """
    Describe a specific data source in QuickSight.
    
    Args:
        data_source_id: ID of the data source to describe
        
    Returns:
        Data source description
    """
    client = get_quicksight_client()
    response = client.describe_data_source(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DataSourceId=data_source_id
    )
    return response.get('DataSource', {})

@mcp.tool()
async def get_dashboard_embed_url(dashboard_id: str) -> str:
    """
    Get the embed URL for a QuickSight dashboard.
    
    Args:
        dashboard_id: ID of the dashboard
        
    Returns:
        Embed URL for the dashboard
    """
    client = get_quicksight_client()
    response = client.generate_embed_url_for_registered_user(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        UserArn=os.getenv('QUICKSIGHT_USER_ARN'),
        SessionLifetimeInMinutes=100,
        AllowedDomains=['http://localhost:3000'],
        ExperienceConfiguration={
            'Dashboard': {
                'InitialDashboardId': dashboard_id
            }
        }
    )
    return response.get('EmbedUrl', '')

@mcp.tool()
async def create_dashboard(
    dashboard_id: str,
    name: str,
    source_entity: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create a new QuickSight dashboard.
    
    Args:
        dashboard_id: ID for the new dashboard
        name: Name of the dashboard
        source_entity: Source entity configuration
        
    Returns:
        Dashboard creation response
    """
    client = get_quicksight_client()
    response = client.create_dashboard(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id,
        Name=name,
        SourceEntity=source_entity
    )
    return response

if __name__ == "__main__":
    # Initialize and run the MCP server
    mcp.run(transport='stdio')
