import logging
from dataclasses import dataclass
from fastmcp import Context, FastMCP
from typing import Any


logger = logging.getLogger(__name__)

mcp = FastMCP[Any](
    name='Simple MCP Server',
    instructions=('Simple MCP Server used in Integ Tests'),
)

##### Generic Tool Testing


@mcp.tool
def greet(name: str):
    """MCP Tool which is very simple for testing."""
    return f'Hello {name}'


##### Elicitation Testing


@dataclass
class ElicitationWithAccept:
    """Class type when requesting Elicitation and expecting it to be accepted."""

    value: str


@dataclass
class ElicitationWithDecline:
    """Class type when requesting Elicitation and expecting it to be declined."""

    value: str


@mcp.tool
async def elicit_for_my_name(elicitation_expected: str, ctx: Context):
    """MCP Tool which supports elicitation."""
    response_type = ElicitationWithAccept

    if 'Decline' in elicitation_expected:
        response_type = ElicitationWithDecline

    result = await ctx.elicit(message='What is your name?', response_type=response_type)

    if result.action == 'accept':
        return f'Nice to meet you - {result.data.value}'
    elif result.action == 'decline':
        return 'Information not provided'
    else:
        return 'cancelled'


#### Server Setup


def main():
    """Main entrypoint for running this MCP Server."""
    logger.info('Starting Simple MCP Server')

    mcp.run(
        transport='http',
        host='0.0.0.0',
        port=8000,
        # By default, this param is set to False to ensure the Elicitation feature is working
        # When deploying to AgentCore, this flag must be set to True for MCP to work
        stateless_http=False,
    )


if __name__ == '__main__':
    main()
