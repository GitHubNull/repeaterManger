<#-- 越权测试用例内容片段：供 test_cases.ftl（独立文档）和 html_report.ftl（单文件嵌入）复用 -->

<#-- ========== 测试方法说明 ========== -->
<div class="test-methodology-explanation">
  <h3>测试方法说明</h3>
  <p>本报告中的测试用例采用会话替换和移除策略来模拟越权攻击，具体原理如下：</p>

  <div class="methodology-section">
    <h4>1. 会话替换测试原理</h4>
    <p><strong>目的：</strong>验证服务端是否正确实施了基于角色的权限控制</p>
    <p><strong>方法：</strong>将高权限用户的请求中的认证信息替换为低权限用户的凭证</p>
    <p><strong>攻击场景对应：</strong>模拟攻击者获取低权限账户后尝试访问高权限功能</p>
    <p><strong>为什么有效：</strong>能够发现服务端仅在前端隐藏功能而未在接口层面做权限验证的缺陷</p>
  </div>

  <div class="methodology-section">
    <h4>2. 会话移除测试原理</h4>
    <p><strong>目的：</strong>验证服务端是否正确实施了身份认证机制</p>
    <p><strong>方法：</strong>移除请求中的所有认证信息（Cookie、Authorization头等）</p>
    <p><strong>攻击场景对应：</strong>模拟未认证攻击者直接访问需要认证的接口</p>
    <p><strong>为什么有效：</strong>能够发现服务端认证机制缺失或绕过的问题</p>
  </div>

  <div class="methodology-section">
    <h4>3. 测试方法与真实攻击的关系</h4>
    <p><strong>相似性：</strong>都试图以低权限身份访问高权限资源</p>
    <p><strong>差异性：</strong>测试使用系统化的用例覆盖常见场景，而真实攻击可能使用更复杂的绕过技术</p>
    <p><strong>互补性：</strong>测试发现基础权限控制缺陷，真实攻击可能发现更复杂的逻辑漏洞</p>
  </div>
</div>

<#-- ========== 未授权访问 ========== -->
<h2>未授权访问（Unauthorized Access）</h2>
<p style="margin-bottom:16px;color:#555;">未授权访问是指攻击者在没有任何有效身份凭证的情况下，直接访问需要认证的接口或资源。此类漏洞通常由于服务端缺少身份验证中间件或验证逻辑被绕过导致。</p>

<div class="testcase-principle">
  <h4>测试原理说明</h4>
  <p><strong>为什么使用会话移除策略：</strong></p>
  <ul>
    <li><strong>模拟真实攻击：</strong>攻击者通常会尝试在没有任何有效凭证的情况下直接访问受保护资源</li>
    <li><strong>验证认证机制：</strong>通过移除所有认证信息，验证服务端是否正确实施了身份验证检查</li>
    <li><strong>发现认证缺陷：</strong>检测服务端是否存在认证绕过或认证机制缺失的问题</li>
  </ul>
  
  <p><strong>与真实攻击的异同：</strong></p>
  <ul>
    <li><strong>相同点：</strong>都尝试在无有效凭证的情况下访问受保护资源</li>
    <li><strong>不同点：</strong>测试使用系统化的方法移除认证信息，而真实攻击可能使用更复杂的绕过技术</li>
    <li><strong>原因：</strong>测试目的是验证认证机制的有效性，而非完全模拟攻击者的所有可能行为</li>
  </ul>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge unauthorized">未授权访问</span> TC-UA-001 匿名访问认证接口</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>攻击者未登录系统，直接请求需要身份认证的 API 接口。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>目标系统存在需要登录才能访问的接口；攻击者无任何有效会话或令牌。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 以已登录用户身份正常请求目标接口，记录完整请求报文（含 Cookie / Authorization 头）
2. 移除请求中所有身份认证信息（Cookie、Authorization、Token 等）
3. 发送匿名请求到目标接口
4. 观察响应状态码和响应体内容</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端返回 401 Unauthorized 或 403 Forbidden，响应体不包含敏感数据。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若匿名请求返回 200 且响应体包含与已登录用户相同或部分相同的数据，则存在未授权访问漏洞。</div>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge unauthorized">未授权访问</span> TC-UA-002 过期/无效令牌访问</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>攻击者使用已过期或被篡改的令牌（Token）请求需要认证的接口。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>目标系统使用基于令牌的认证机制（如 JWT、Bearer Token）；攻击者持有过期或伪造的令牌。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 获取一个有效的认证令牌（通过正常登录）
2. 等待令牌过期，或手动篡改令牌内容（如修改签名部分）
3. 使用过期/篡改后的令牌请求目标接口
4. 观察服务端是否正确拒绝该请求</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端验证令牌有效性，拒绝过期或篡改的令牌，返回 401 状态码。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若服务端接受过期或篡改的令牌并返回正常数据，则存在令牌验证缺陷。</div>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge unauthorized">未授权访问</span> TC-UA-003 缺失认证头访问</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>攻击者通过移除 HTTP 请求中的认证头（Authorization、Cookie），尝试绕过身份验证。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>目标接口依赖 HTTP 头部进行身份认证；服务端未对缺失认证头的情况做统一拦截。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 捕获已认证用户的完整请求报文
2. 使用 Burp Repeater 编辑请求，删除 Authorization 头和 Cookie 头
3. 发送修改后的请求
4. 对比删除认证头前后的响应差异</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端检测到缺失认证信息，返回 401/403 或重定向到登录页面。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若缺失认证头的请求仍返回 200 且包含业务数据，则存在认证绕过漏洞。</div>
</div>

<#-- ========== 垂直越权 ========== -->
<h2>垂直越权（Vertical Privilege Escalation）</h2>
<p style="margin-bottom:16px;color:#555;">垂直越权是指低权限用户访问或操作高权限角色专属的接口或功能。此类漏洞通常由于服务端仅在前端做了权限控制，而未在服务端接口层面做角色权限校验导致。</p>

<div class="testcase-principle">
  <h4>测试原理说明</h4>
  <p><strong>为什么使用会话替换策略：</strong></p>
  <ul>
    <li><strong>模拟真实攻击：</strong>攻击者通常会尝试使用低权限账户访问高权限功能</li>
    <li><strong>验证权限控制：</strong>通过替换会话，验证服务端是否正确实施了基于角色的权限检查</li>
    <li><strong>发现权限缺陷：</strong>检测服务端是否仅依赖前端控制而未在接口层面做权限验证</li>
  </ul>
  
  <p><strong>与真实攻击的异同：</strong></p>
  <ul>
    <li><strong>相同点：</strong>都尝试使用低权限身份访问高权限资源</li>
    <li><strong>不同点：</strong>测试使用预定义的测试用例，而真实攻击可能使用更复杂的绕过技术</li>
    <li><strong>原因：</strong>测试目的是验证权限控制机制的有效性，而非完全模拟攻击者的所有可能行为</li>
  </ul>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge vertical">垂直越权</span> TC-VP-001 普通用户访问管理员接口</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>普通用户（如 role=user）尝试访问仅管理员（role=admin）可用的 API 接口。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>系统中存在不同权限级别的角色（如 admin、user）；已知管理员专属接口的 URL 和参数。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 以管理员身份登录，访问管理员专属接口（如用户管理、系统配置），记录请求报文
2. 以普通用户身份登录，获取普通用户的认证凭证（Cookie / Token）
3. 将管理员接口请求中的认证信息替换为普通用户的凭证
4. 发送请求，观察服务端是否正确拒绝</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端识别普通用户角色，拒绝访问管理员接口，返回 403 Forbidden。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若普通用户的凭证可以成功调用管理员接口并返回数据，则存在垂直越权漏洞。</div>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge vertical">垂直越权</span> TC-VP-002 角色提升</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>攻击者通过修改请求中的角色/权限参数，尝试将自身权限提升为更高角色。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>目标系统存在角色管理接口；请求参数中包含角色标识字段（如 role、type、level）。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 以普通用户身份登录，找到修改个人信息的接口
2. 分析请求参数，查找可能控制角色的字段（如 role、userType、isAdmin）
3. 修改角色字段值为高权限角色（如将 role=user 改为 role=admin）
4. 发送请求，检查是否成功提升权限
5. 验证提升后的权限是否生效（尝试访问管理员接口）</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端忽略或拒绝客户端提交的角色修改请求，角色变更仅由管理员操作。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若修改角色字段后用户权限实际提升，则存在角色提升漏洞。</div>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge vertical">垂直越权</span> TC-VP-003 功能级越权</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>普通用户尝试执行高危操作（如批量删除、数据导出、系统配置修改），这些操作通常仅管理员可用。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>系统存在功能级权限控制（如某些按钮仅管理员可见）；攻击者已知高危操作的接口地址。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 以管理员身份执行高危操作（如批量删除用户、导出全部数据），记录请求报文
2. 以普通用户身份，使用普通用户的凭证重放该请求
3. 观察服务端是否执行了该操作
4. 检查操作结果（如数据是否被删除、导出文件是否生成）</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端在接口层面校验用户角色，拒绝普通用户执行高危操作。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若普通用户成功执行了高危操作，则存在功能级垂直越权漏洞。</div>
</div>

<#-- ========== 水平越权 ========== -->
<h2>水平越权（Horizontal Privilege Escalation）</h2>
<p style="margin-bottom:16px;color:#555;">水平越权是指同级别用户之间互相访问或操作对方的数据。此类漏洞通常由于服务端仅验证了用户身份，但未验证请求中的资源归属关系导致。</p>

<div class="testcase-principle">
  <h4>测试原理说明</h4>
  <p><strong>为什么使用会话替换策略：</strong></p>
  <ul>
    <li><strong>模拟真实攻击：</strong>攻击者通常会尝试访问其他同级别用户的数据</li>
    <li><strong>验证资源归属检查：</strong>通过替换会话，验证服务端是否正确实施了资源归属验证</li>
    <li><strong>发现数据访问缺陷：</strong>检测服务端是否仅验证用户身份而未验证资源归属关系</li>
  </ul>
  
  <p><strong>与真实攻击的异同：</strong></p>
  <ul>
    <li><strong>相同点：</strong>都尝试访问其他用户的数据</li>
    <li><strong>不同点：</strong>测试使用系统化的方法替换会话，而真实攻击可能使用更复杂的参数篡改技术</li>
    <li><strong>原因：</strong>测试目的是验证资源归属检查机制的有效性，而非完全模拟攻击者的所有可能行为</li>
  </ul>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge horizontal">水平越权</span> TC-HP-001 IDOR 直接对象引用</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>攻击者通过修改请求中的资源 ID（如用户 ID、订单 ID），访问其他用户的数据。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>目标接口通过 URL 路径或请求参数传递资源 ID；资源 ID 可预测（如自增整数）。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 以用户 A 身份登录，访问自己的资源（如 /api/users/1001/profile），记录请求
2. 将请求中的资源 ID 修改为用户 B 的 ID（如 /api/users/1002/profile）
3. 使用用户 A 的认证凭证发送修改后的请求
4. 观察是否返回了用户 B 的数据</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端验证资源归属，拒绝用户 A 访问用户 B 的数据，返回 403 或 404。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若修改资源 ID 后返回了其他用户的数据，则存在 IDOR 水平越权漏洞。</div>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge horizontal">水平越权</span> TC-HP-002 批量遍历</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>攻击者通过遍历资源 ID 范围，批量获取系统中其他用户的数据。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>目标接口存在 IDOR 漏洞；资源 ID 为可遍历的值（如连续整数）。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 确认目标接口存在 IDOR 漏洞（参考 TC-HP-001）
2. 确定资源 ID 的有效范围（如用户 ID 从 1001 到 9999）
3. 编写脚本或使用 Burp Intruder 遍历 ID 范围
4. 收集所有返回有效数据的响应
5. 统计可获取的数据量和敏感程度</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端对每个请求都验证资源归属，遍历请求均返回 403/404。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若遍历请求返回了多条其他用户的数据，则存在批量数据泄露风险。漏洞严重程度与可遍历的数据量成正比。</div>
</div>

<div class="testcase-section">
  <div class="endpoint-header">
    <div>
      <h3><span class="testcase-type-badge horizontal">水平越权</span> TC-HP-003 参数篡改</h3>
    </div>
  </div>
  <div class="testcase-field"><span class="field-label">测试场景</span>攻击者通过修改请求体中的用户标识字段（如 userId、username、email），操作其他用户的数据。</div>
  <div class="testcase-field"><span class="field-label">前置条件</span>目标接口在请求体中接收用户标识参数；服务端未校验该参数与当前认证用户的一致性。</div>
  <div class="testcase-field"><span class="field-label">测试步骤</span></div>
  <pre>1. 以用户 A 身份登录，找到操作用户数据的接口（如修改密码、更新资料）
2. 分析请求体，查找标识用户身份的字段（如 userId、username、email）
3. 将该字段值修改为用户 B 的标识
4. 发送请求，检查是否成功修改了用户 B 的数据
5. 尝试多种参数位置：URL 参数、JSON Body、表单字段</pre>
  <div class="testcase-field"><span class="field-label">预期结果</span>服务端忽略请求体中的用户标识字段，或校验其与当前认证用户一致，拒绝不一致的请求。</div>
  <div class="testcase-field"><span class="field-label">判定标准</span>若修改用户标识字段后成功操作了其他用户的数据，则存在参数篡改水平越权漏洞。</div>
</div>
