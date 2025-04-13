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
async def list_dashboards() -> List[Dict[str, Any]]:
    """
    List all dashboards in QuickSight account.
    
    Returns:
        List of dashboard information
    """
    client = get_quicksight_client()
    response = client.list_dashboards(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account']
    )
    return response.get('DashboardSummaryList', [])

@mcp.tool()
async def describe_dashboard(dashboard_id: str) -> Dict[str, Any]:
    """
    Get basic information about a QuickSight dashboard including its name, version, status, and creation details.
    Use this to get an overview of a dashboard's metadata and current state.
    
    Args:
        dashboard_id: ID of the dashboard to describe
        
    Returns:
        Dashboard description including metadata and status
    """
    client = get_quicksight_client()
    response = client.describe_dashboard(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id
    )
    return response.get('Dashboard', {})

@mcp.tool()
async def describe_dashboard_definition(dashboard_id: str) -> Dict[str, Any]:
    """
    Get the complete definition of a QuickSight dashboard including all its visualizations, layouts, and configurations.
    Use this when you need to understand the dashboard's structure, visualizations, or want to replicate its design.
    
    Args:
        dashboard_id: ID of the dashboard to describe
        
    Returns:
        Complete dashboard definition including all visualizations and layouts
    """
    client = get_quicksight_client()
    response = client.describe_dashboard_definition(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id
    )
    return response.get('Definition', {})

@mcp.tool()
async def describe_dashboard_permissions(dashboard_id: str) -> Dict[str, Any]:
    """
    Get the permissions and access control settings for a QuickSight dashboard.
    Use this to understand who has access to the dashboard and what level of access they have.
    
    Args:
        dashboard_id: ID of the dashboard to describe
        
    Returns:
        Dashboard permissions including IAM policies and user/group access
    """
    client = get_quicksight_client()
    response = client.describe_dashboard_permissions(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id
    )
    return response.get('Permissions', {})

@mcp.tool()
async def describe_dashboard_snapshot_job(dashboard_id: str, snapshot_job_id: str) -> Dict[str, Any]:
    """
    Get the status and details of a specific dashboard snapshot job.
    Use this to check the progress of a snapshot generation or to get information about a completed snapshot.
    
    Args:
        dashboard_id: ID of the dashboard
        snapshot_job_id: ID of the snapshot job to describe
        
    Returns:
        Snapshot job status and details
    """
    client = get_quicksight_client()
    response = client.describe_dashboard_snapshot_job(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id,
        SnapshotJobId=snapshot_job_id
    )
    return response.get('SnapshotJob', {})

@mcp.tool()
async def describe_dashboard_snapshot_job_result(dashboard_id: str, snapshot_job_id: str) -> Dict[str, Any]:
    """
    Get the results of a completed dashboard snapshot job, including the generated snapshot URL.
    Use this to retrieve the actual snapshot after a job has completed successfully.
    
    Args:
        dashboard_id: ID of the dashboard
        snapshot_job_id: ID of the snapshot job
        
    Returns:
        Snapshot job results including the generated snapshot URL
    """
    client = get_quicksight_client()
    response = client.describe_dashboard_snapshot_job_result(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id,
        SnapshotJobId=snapshot_job_id
    )
    return response.get('Result', {})

@mcp.tool()
async def describe_dashboards_qa_configuration(dashboard_id: str) -> Dict[str, Any]:
    """
    Get the Question and Answer (Q&A) configuration for a QuickSight dashboard.
    Use this to understand how the dashboard's Q&A feature is configured and what questions it can answer.
    
    Args:
        dashboard_id: ID of the dashboard
        
    Returns:
        Q&A configuration details including enabled features and settings
    """
    client = get_quicksight_client()
    response = client.describe_dashboards_qa_configuration(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id
    )
    return response.get('QaConfiguration', {})

@mcp.tool()
async def get_dashboard_embed_url(dashboard_id: str) -> Dict[str, Any]:
    """
    Generates a temporary session URL and authorization code (bearer token) for embedding a QuickSight dashboard.
    Use this to embed a read-only dashboard in your website or application.
    
    Args:
        dashboard_id: ID of the dashboard to embed
        
    Returns:
        Dictionary containing embed URL and status
    """
    client = get_quicksight_client()
    response = client.get_dashboard_embed_url(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id,
        IdentityType='QUICKSIGHT',
        SessionLifetimeInMinutes=60,
        Namespace='default',
        UserArn=os.getenv('QUICKSIGHT_USER_ARN')
    )
    return response

@mcp.tool()
async def create_dashboard(
    dashboard_id: str,
    name: str,
    **kwargs
) -> Dict[str, Any]:
    """
    Create a new QuickSight dashboard.
    
    Args:
        dashboard_id: ID for the new dashboard
        name: Name of the dashboard
        **kwargs: Additional configuration for the dashboard - refer to https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CreateDashboard.html
        
    Returns:
        Dashboard creation response
    """
    client = get_quicksight_client()
    response = client.create_dashboard(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        DashboardId=dashboard_id,
        Name=name,
        **kwargs
    )
    return response

@mcp.tool()
async def create_analysis(
    analysis_id: str,
    name: str,
    **kwargs
) -> Dict[str, Any]:
    """
    Create a new QuickSight analysis.
    An analysis is a reusable template that can be used to create dashboards.
    Use this to create a new analysis with specific data sources and visualizations.
    
    Args:
        analysis_id: Unique identifier for the analysis
        name: Name of the analysis
        **kwargs: Additional configuration for the analysis - refer to https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CreateAnalysis.html
        
    Returns:
        Analysis creation response
    """
    client = get_quicksight_client()
    response = client.create_analysis(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        AnalysisId=analysis_id,
        Name=name,
        **kwargs
    )
    return response

@mcp.tool()
async def describe_analysis(analysis_id: str) -> Dict[str, Any]:
    """
    Get basic information about a QuickSight analysis including its name, status, and creation details.
    Use this to get an overview of an analysis's metadata and current state.
    
    Args:
        analysis_id: ID of the analysis to describe
        
    Returns:
        Analysis description including metadata and status
    """
    client = get_quicksight_client()
    response = client.describe_analysis(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        AnalysisId=analysis_id
    )
    return response.get('Analysis', {})

@mcp.tool()
async def describe_analysis_definition(analysis_id: str) -> Dict[str, Any]:
    """
    Get the complete definition of a QuickSight analysis including all its visualizations, layouts, and configurations.
    Use this when you need to understand the analysis's structure, visualizations, or want to replicate its design.
    
    Args:
        analysis_id: ID of the analysis to describe
        
    Returns:
        Complete analysis definition including all visualizations and layouts
    """
    client = get_quicksight_client()
    response = client.describe_analysis_definition(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        AnalysisId=analysis_id
    )
    return response.get('Definition', {})

@mcp.tool()
async def describe_analysis_permissions(analysis_id: str) -> Dict[str, Any]:
    """
    Get the permissions and access control settings for a QuickSight analysis.
    Use this to understand who has access to the analysis and what level of access they have.
    
    Args:
        analysis_id: ID of the analysis to describe
        
    Returns:
        Analysis permissions including IAM policies and user/group access
    """
    client = get_quicksight_client()
    response = client.describe_analysis_permissions(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account'],
        AnalysisId=analysis_id
    )
    return response.get('Permissions', {})

@mcp.tool()
async def list_analyses() -> List[Dict[str, Any]]:
    """
    List all analyses in QuickSight account.
    
    Returns:
        List of analysis information
    """
    client = get_quicksight_client()
    response = client.list_analyses(
        AwsAccountId=boto3.client('sts').get_caller_identity()['Account']
    )
    return response.get('AnalysisSummaryList', [])

if __name__ == "__main__":
    # Initialize and run the MCP server
    mcp.run(transport='stdio')
