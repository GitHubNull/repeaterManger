# Security Disclaimer / 安全免责声明

## English

### Intended Use

Repeater Manager ("the Software") is a Burp Suite extension designed for **legitimate security testing, vulnerability assessment, and penetration testing** purposes only. The Software is intended to be used by security professionals, researchers, and authorized penetration testers who have proper authorization to test the target systems.

### Legal Compliance

Users of this Software are solely responsible for ensuring that their use complies with all applicable local, national, and international laws and regulations. This includes, but is not limited to:

- Obtaining proper written authorization before testing any systems
- Complying with computer fraud and abuse laws
- Respecting privacy and data protection regulations
- Adhering to intellectual property laws

### No Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Assumption of Risk

Use of this Software for unauthorized access to computer systems, data theft, disruption of services, or any other illegal activities is **strictly prohibited**. The developers assume no liability for any misuse of the Software. Users who engage in unauthorized activities bear full legal responsibility for their actions.

### Data Security

- The Software stores HTTP request and response data locally in SQLite databases
- ERM archive export supports AES-256-CBC encryption with HMAC-SHA256 integrity verification
- Users are responsible for securing their data and encryption passwords
- The Software does not transmit any collected data to external servers

### Reporting Security Issues

If you discover a security vulnerability in the Software itself, please report it responsibly by opening a GitHub Issue or contacting the maintainers directly. Do not publicly disclose security vulnerabilities before they have been addressed.

---

## 中文

### 预期用途

Repeater Manager（"本软件"）是一个 Burp Suite 扩展插件，**仅用于合法的安全测试、漏洞评估和渗透测试**目的。本软件面向安全专业人员、研究人员和经授权的渗透测试人员使用，且使用者必须已获得对目标系统进行测试的适当授权。

### 法律合规

本软件的使用者需自行确保其使用行为符合所有适用的地方、国家和国际法律法规，包括但不限于：

- 在测试任何系统之前获得适当的书面授权
- 遵守计算机欺诈和滥用法
- 尊重隐私和数据保护法规
- 遵守知识产权法

### 免责声明

本软件按"原样"提供，不提供任何形式的明示或暗示保证，包括但不限于适销性、特定用途的适用性和非侵权性保证。在任何情况下，作者或版权持有人均不对因使用本软件而产生的任何索赔、损害或其他责任负责，无论是在合同诉讼、侵权行为还是其他方面。

### 风险承担

**严禁**将本软件用于未经授权访问计算机系统、数据窃取、服务中断或任何其他非法活动。开发者对软件的任何滥用不承担任何责任。从事未经授权活动的使用者需自行承担全部法律责任。

### 数据安全

- 本软件将 HTTP 请求和响应数据存储在本地 SQLite 数据库中
- ERM 存档导出支持 AES-256-CBC 加密及 HMAC-SHA256 完整性校验
- 使用者有责任保护其数据和加密密码的安全
- 本软件不会将收集的任何数据传输到外部服务器

### 安全问题报告

如果您发现本软件本身存在安全漏洞，请通过 GitHub Issue 或直接联系维护者进行负责任的报告。在安全漏洞被修复之前，请勿公开披露。
