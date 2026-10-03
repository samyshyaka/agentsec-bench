import os
from dotenv import load_dotenv
from anthropic import Anthropic
from ..core.agent import Agent
from ..core.types import Tool, ToolCall

load_dotenv()

MAX_TOOL_TURNS = 5


def tool_to_anthropic_schema(tool: Tool) -> dict:
    schema = tool.parameters.model_json_schema()
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": schema,
    }


class AnthropicAgent(Agent):
    name = "anthropic-live-agent"
    role = "default"

    def __init__(self, model: str = "claude-3-haiku-20240307"):
        self.model = model
        self.client = Anthropic()

    def query(self, prompt, tools, env):
        anthropic_tools = [tool_to_anthropic_schema(t) for t in tools]
        tools_by_name = {t.name: t for t in tools}

        messages = [{"role": "user", "content": prompt}]
        full_trace: list[ToolCall] = []
        final_text = "(no response)"

        for _ in range(MAX_TOOL_TURNS):
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                system="You are a helpful assistant with access to tools.",
                messages=messages,
                tools=anthropic_tools,
            )

            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
            text_blocks = [b.text for b in response.content if b.type == "text"]

            if not tool_use_blocks:
                final_text = "".join(text_blocks)
                break

            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in tool_use_blocks:
                full_trace.append(ToolCall(tool_name=block.name, args=block.input))

                tool = tools_by_name.get(block.name)
                if tool is None:
                    result = f"Error: unknown tool '{block.name}'"
                else:
                    try:
                        result = tool.run(**block.input)
                    except Exception as e:
                        result = f"Error running tool '{block.name}': {e}"

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(result),
                })

            messages.append({"role": "user", "content": tool_results})
        else:
            final_text = "(stopped: max tool turns reached)"

        return [{"role": "assistant", "content": final_text}], full_trace