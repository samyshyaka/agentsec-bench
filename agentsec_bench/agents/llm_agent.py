import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from ..core.agent import Agent
from ..core.types import Tool, ToolCall

load_dotenv()

MAX_TOOL_TURNS = 5


def tool_to_openai_schema(tool: Tool) -> dict:
    schema = tool.parameters.model_json_schema()
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": schema,
        },
    }


class OpenAIAgent(Agent):
    name = "openai-live-agent"
    role = "default"

    def __init__(self, model: str = "gpt-4o-mini-2024-07-18"):
        self.model = model
        self.client = OpenAI()

    def query(self, prompt, tools, env):
        openai_tools = [tool_to_openai_schema(t) for t in tools]
        tools_by_name = {t.name: t for t in tools}

        messages = [
            {"role": "system", "content": "You are a helpful assistant with access to tools."},
            {"role": "user", "content": prompt},
        ]

        full_trace: list[ToolCall] = []
        final_messages = [{"role": "assistant", "content": "(no response)"}]

        for _ in range(MAX_TOOL_TURNS):
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=openai_tools,
            )
            msg = response.choices[0].message

            if not msg.tool_calls:
                final_messages = [{"role": "assistant", "content": msg.content}]
                break

            messages.append({
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ],
            })

            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                full_trace.append(ToolCall(tool_name=tc.function.name, args=args))

                tool = tools_by_name.get(tc.function.name)
                if tool is None:
                    result = f"Error: unknown tool '{tc.function.name}'"
                else:
                    try:
                        result = tool.run(**args)
                    except Exception as e:
                        result = f"Error running tool '{tc.function.name}': {e}"

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(result),
                })
        else:
            final_messages = [{"role": "assistant", "content": "(stopped: max tool turns reached)"}]

        return final_messages, full_trace