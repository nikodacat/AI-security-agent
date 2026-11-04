"""The agy engine: argv shape, reply parsing and failure modes (no agy binary needed)."""
import asyncio
import json
import unittest
from unittest import mock

from exposure_analyzer import agent


class _Proc:
    def __init__(self, out: bytes, err: bytes = b"", rc: int = 0):
        self._out, self._err, self.returncode = out, err, rc

    async def communicate(self):
        return self._out, self._err

    def kill(self):
        pass


def _run(out: bytes, **kw):
    seen = {}

    async def fake_exec(*argv, **opts):
        seen["argv"], seen["opts"] = argv, opts
        return _Proc(out)

    fn = agent.build_agy_verdict_fn(agy_path="agy-stub", **kw)
    with mock.patch("asyncio.create_subprocess_exec", fake_exec):
        return asyncio.run(fn("SYSTEM", "USER")), seen


class AgyEngine(unittest.TestCase):
    def test_reply_is_the_response_field_and_the_call_is_sandboxed(self):
        reply, seen = _run(json.dumps({"status": "SUCCESS", "response": '{"verdict": "CONFIRMED"}'}).encode(),
                           model="gemini-3.8-flash-high")
        self.assertEqual(reply, '{"verdict": "CONFIRMED"}')
        argv = seen["argv"]
        self.assertEqual(argv[0], "agy-stub")
        self.assertEqual(argv[argv.index("--model") + 1], "gemini-3.8-flash-high")
        self.assertEqual(argv[argv.index("--mode") + 1], "plan")
        self.assertNotIn("--dangerously-skip-permissions", argv)
        prompt = argv[argv.index("-p") + 1]
        self.assertTrue(prompt.startswith("SYSTEM") and "USER" in prompt)
        self.assertNotEqual(seen["opts"]["cwd"], ".")  # a throwaway directory, not the repo

    def test_a_failed_status_raises(self):
        with self.assertRaisesRegex(RuntimeError, "ERROR"):
            _run(json.dumps({"status": "ERROR"}).encode())

    def test_non_json_output_raises(self):
        with self.assertRaisesRegex(RuntimeError, "non-JSON"):
            _run(b"not json")

    def test_an_oversized_prompt_is_refused_before_launching(self):
        fn = agent.build_agy_verdict_fn(agy_path="agy-stub")
        with self.assertRaisesRegex(RuntimeError, "chars"):
            asyncio.run(fn("S", "x" * 30000))


if __name__ == "__main__":
    unittest.main()
