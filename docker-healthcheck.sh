#!/bin/sh

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Local stdio liveness only; do not contact the backend or resolve credentials.
if ! tr '\000' '\n' < /proc/1/cmdline |
  head -n 2 |
  grep -Eq '(^|/)(mcp-proxy-for-aws(-cli)?|aws[.]mcp-proxy-for-aws)$'; then
  echo "PID 1 is not the MCP proxy"
  exit 1
fi

for fd in 0 1; do
  target=$(readlink "/proc/1/fd/$fd") || exit 1
  case "$target" in
    pipe:\[*\]|socket:\[*\]) ;;
    *)
      echo "Proxy stdio fd $fd is not a pipe or socket"
      exit 1
      ;;
  esac
done

echo "Proxy stdio is live"
exit 0
