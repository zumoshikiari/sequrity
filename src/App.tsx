import { useState, useCallback } from 'react';
import { analyzeCode, getSeverityBadge, getSeverityIcon, Vulnerability } from './utils/vulnerabilityRules';

function App() {
  const [code, setCode] = useState('');
  const [filename, setFilename] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterCategory, setFilterCategory] = useState<string>('all');

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFilename(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        setCode(content);
      };
      reader.readAsText(file);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) {
      setFilename(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        setCode(content);
      };
      reader.readAsText(file);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
  }, []);

  const handleScan = useCallback(() => {
    if (!code.trim()) return;
    setIsScanning(true);
    setHasScanned(false);
    setSelectedVuln(null);

    setTimeout(() => {
      const results = analyzeCode(code, filename);
      setVulnerabilities(results);
      setIsScanning(false);
      setHasScanned(true);
    }, 1500);
  }, [code, filename]);

  const handleClear = useCallback(() => {
    setCode('');
    setFilename('');
    setVulnerabilities([]);
    setHasScanned(false);
    setSelectedVuln(null);
    setFilterSeverity('all');
    setFilterCategory('all');
  }, []);

  const filteredVulnerabilities = vulnerabilities.filter(v => {
    if (filterSeverity !== 'all' && v.severity !== filterSeverity) return false;
    if (filterCategory !== 'all' && v.category !== filterCategory) return false;
    return true;
  });

  const severityCounts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    info: vulnerabilities.filter(v => v.severity === 'info').length,
  };

  const categories = [...new Set(vulnerabilities.map(v => v.category))];
  const evasionTechniques = vulnerabilities.filter(v => v.evasionTechnique);

  const overallRisk = severityCounts.critical > 0 ? 'КРИТИЧЕСКИЙ'
    : severityCounts.high > 0 ? 'ВЫСОКИЙ'
    : severityCounts.medium > 0 ? 'СРЕДНИЙ'
    : severityCounts.low > 0 ? 'НИЗКИЙ'
    : 'БЕЗОПАСНЫЙ';

  const riskColor = severityCounts.critical > 0 ? 'text-red-500'
    : severityCounts.high > 0 ? 'text-orange-500'
    : severityCounts.medium > 0 ? 'text-yellow-500'
    : severityCounts.low > 0 ? 'text-blue-500'
    : 'text-emerald-500';

  const loadEvasionExample = () => {
    setCode(`// ==========================================
// ПРИМЕР: Попытка обойти сканер уязвимостей
// ==========================================

// --- 1. Обход eval() ---
const userInput = getUserInput();

// Попытка 1: indirect eval
(0, eval)(userInput);

// Попытка 2: bracket notation
window["ev" + "al"](userInput);

// Попытка 3: Function constructor
const Fn = Function;
new Fn(userInput)();

// Попытка 4: setTimeout со строкой
setTimeout("processData(" + userInput + ")", 0);

// Попытка 5: Unicode escape
const fn = "\\x65\\x76\\x61\\x6c";
window[fn](userInput);

// --- 2. Обход XSS ---
const html = getUntrustedContent();

// Попытка 1: insertAdjacentHTML вместо innerHTML
element.insertAdjacentHTML("beforeend", html);

// Попытка 2: createContextualFragment
const range = document.createRange();
const frag = range.createContextualFragment(html);

// Попытка 3: outerHTML
element.outerHTML = html;

// Попытка 4: обфусцированный document.write
const w = "wr" + "ite";
document[w](html);

// --- 3. Обход SQL-инъекций ---
const userId = req.query.id;

// Попытка 1: template literal
const q1 = \`SELECT * FROM users WHERE id = \${userId}\`;

// Попытка 2: Array.join
const parts = ["SELECT * FROM users WHERE id =", userId];
const q2 = parts.join(" ");

// Попытка 3: String.concat
const q3 = "SELECT * FROM users WHERE id = ".concat(userId);

// Попытка 4: String.replace
const q4 = "SELECT * FROM users WHERE id = {{ID}}".replace("{{ID}}", userId);

// --- 4. Обход хардкода секретов ---

// Попытка 1: Base64
const secret = atob("c3VwZXJfc2VjcmV0X3Bhc3N3b3Jk");

// Попытка 2: разбиение на части
const p1 = "sup";
const p2 = "er_";
const p3 = "secret";
const password = p1 + p2 + p3;

// Попытка 3: String.fromCharCode
const apiKey = String.fromCharCode(115, 107, 45, 49, 50, 51, 52, 53, 54, 55);

// Попытка 4: fallback пароль
const dbPass = process.env.DB_PASS || "default_password_123";

// Попытка 5: XOR encoding
const key = [83, 101, 99, 114, 101, 116];
const decoded = key.map(c => String.fromCharCode(c ^ 0)).join("");

// --- 5. Обход Command Injection ---
const { exec } = require("child_process");
exec("ls " + userInput);

const { spawn } = require("child_process");
spawn("sh", ["-c", userInput], { shell: true });

// --- 6. Обход CORS ---
res.setHeader("Access-Control-Allow-Origin", "*");

// --- 7. Обход SSRF ---
const target = "http://" + userInput + "/admin";
fetch(target);

const url2 = \`https://\${userInput}/internal\`;
fetch(url2);

// --- 8. Высокоэнтропийная строка (закодированный ключ) ---
const hiddenKey = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCBrZXk=";
const decoded2 = atob(hiddenKey);`);
    setFilename('evasion-attempt.js');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-slate-700/50 backdrop-blur-sm bg-slate-900/50 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-500 flex items-center justify-center text-xl font-bold shadow-lg shadow-emerald-500/20">
              🛡️
            </div>
            <div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
                VulnScanner v2.0
              </h1>
              <p className="text-xs text-slate-400">Анализ уязвимостей + обнаружение обходов</p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span className="hidden sm:flex items-center gap-1.5 text-xs bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-3 py-1.5 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              Anti-Evasion Engine
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        {/* Input Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Code Input */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-slate-200 flex items-center gap-2">
                <span>📝</span> Исходный код
              </h2>
              {filename && (
                <span className="text-xs bg-slate-700 text-slate-300 px-2 py-1 rounded-md">
                  {filename}
                </span>
              )}
            </div>

            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              className="relative"
            >
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={`Вставьте код для анализа или перетащите файл сюда...\n\nСканер v2.0 обнаруживает:\n• Прямые уязвимости (eval, innerHTML, SQL...)\n• Техники обхода (обфускация, indirect eval...)\n• Закодированные секреты (Base64, XOR, char codes)\n• Высокоэнтропийные строки`}
                className="w-full h-80 bg-slate-800/50 border border-slate-700 rounded-xl p-4 text-sm font-mono text-slate-300 placeholder-slate-500 resize-none focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500/50 transition-all"
                spellCheck={false}
              />
              <div className="absolute bottom-3 right-3 text-xs text-slate-500">
                {code.split('\n').length} строк
              </div>
            </div>

            <div className="flex items-center gap-3">
              <label className="flex-1 cursor-pointer">
                <div className="flex items-center justify-center gap-2 px-4 py-3 bg-slate-800/50 border border-slate-700 border-dashed rounded-xl hover:border-emerald-500/50 hover:bg-slate-800 transition-all text-sm text-slate-400 hover:text-emerald-400">
                  <span>📁</span> Загрузить файл
                </div>
                <input
                  type="file"
                  onChange={handleFileUpload}
                  className="hidden"
                  accept=".js,.ts,.jsx,.tsx,.py,.php,.java,.rb,.go,.rs,.c,.cpp,.cs,.vue,.html,.css,.json,.yml,.yaml,.env,.sql,.sh,.bash"
                />
              </label>
              <button
                onClick={handleScan}
                disabled={!code.trim() || isScanning}
                className="flex-1 px-6 py-3 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-semibold rounded-xl hover:from-emerald-600 hover:to-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-emerald-500/20 hover:shadow-emerald-500/40 flex items-center justify-center gap-2"
              >
                {isScanning ? (
                  <>
                    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Сканирование...
                  </>
                ) : (
                  <>
                    <span>🔍</span> Сканировать
                  </>
                )}
              </button>
              {code && (
                <button
                  onClick={handleClear}
                  className="px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl hover:bg-slate-700 transition-all text-slate-400 hover:text-white"
                >
                  ✕
                </button>
              )}
            </div>
          </div>

          {/* Results Summary */}
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-slate-200 flex items-center gap-2">
              <span>📊</span> Результаты анализа
            </h2>

            {!hasScanned && !isScanning && (
              <div className="h-80 bg-slate-800/30 border border-slate-700/50 rounded-xl flex flex-col items-center justify-center text-slate-500 gap-4">
                <div className="text-6xl opacity-50">🔬</div>
                <p className="text-center px-8">
                  Вставьте код или загрузите файл,<br />
                  затем нажмите «Сканировать»
                </p>
              </div>
            )}

            {isScanning && (
              <div className="h-80 bg-slate-800/30 border border-slate-700/50 rounded-xl flex flex-col items-center justify-center text-slate-400 gap-4">
                <div className="relative">
                  <div className="w-20 h-20 border-4 border-slate-700 rounded-full"></div>
                  <div className="absolute inset-0 w-20 h-20 border-4 border-emerald-500 rounded-full border-t-transparent animate-spin"></div>
                  <div className="absolute inset-0 flex items-center justify-center text-2xl">🛡️</div>
                </div>
                <p className="animate-pulse">Анализ кода и обнаружение обходов...</p>
              </div>
            )}

            {hasScanned && !isScanning && (
              <div className="space-y-4">
                {/* Overall Risk */}
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm text-slate-400">Общий уровень риска</span>
                    <span className={`text-lg font-bold ${riskColor}`}>{overallRisk}</span>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-3 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-1000 ${
                        severityCounts.critical > 0 ? 'bg-red-500 w-full'
                        : severityCounts.high > 0 ? 'bg-orange-500 w-3/4'
                        : severityCounts.medium > 0 ? 'bg-yellow-500 w-1/2'
                        : severityCounts.low > 0 ? 'bg-blue-500 w-1/4'
                        : 'bg-emerald-500 w-8'
                      }`}
                    ></div>
                  </div>
                </div>

                {/* Evasion Techniques Detected */}
                {evasionTechniques.length > 0 && (
                  <div className="bg-red-500/5 border border-red-500/30 rounded-xl p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-lg">🎭</span>
                      <span className="text-sm font-semibold text-red-400">
                        Обнаружено {evasionTechniques.length} техник обхода!
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {[...new Set(evasionTechniques.map(v => v.evasionTechnique))].map((tech, i) => (
                        <span key={i} className="text-[10px] bg-red-500/10 text-red-300 border border-red-500/20 px-2 py-0.5 rounded-full">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Severity Counts */}
                <div className="grid grid-cols-5 gap-2">
                  {Object.entries(severityCounts).map(([severity, count]) => (
                    <button
                      key={severity}
                      onClick={() => setFilterSeverity(filterSeverity === severity ? 'all' : severity)}
                      className={`p-3 rounded-xl border text-center transition-all ${
                        filterSeverity === severity
                          ? 'border-emerald-500 bg-emerald-500/10'
                          : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                      }`}
                    >
                      <div className="text-lg mb-1">{getSeverityIcon(severity as Vulnerability['severity'])}</div>
                      <div className="text-xl font-bold text-white">{count}</div>
                      <div className="text-[10px] text-slate-400 uppercase">
                        {severity === 'critical' ? 'Крит.' : severity === 'high' ? 'Высокий' : severity === 'medium' ? 'Средний' : severity === 'low' ? 'Низкий' : 'Инфо'}
                      </div>
                    </button>
                  ))}
                </div>

                {/* Category Filter */}
                {categories.length > 1 && (
                  <div className="flex flex-wrap gap-1.5">
                    <button
                      onClick={() => setFilterCategory('all')}
                      className={`text-xs px-2.5 py-1 rounded-full transition-all ${
                        filterCategory === 'all'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                      }`}
                    >
                      Все ({vulnerabilities.length})
                    </button>
                    {categories.map(cat => (
                      <button
                        key={cat}
                        onClick={() => setFilterCategory(filterCategory === cat ? 'all' : cat)}
                        className={`text-xs px-2.5 py-1 rounded-full transition-all ${
                          filterCategory === cat
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                        }`}
                      >
                        {cat} ({vulnerabilities.filter(v => v.category === cat).length})
                      </button>
                    ))}
                  </div>
                )}

                {/* Vulnerability List */}
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                  <div className="p-3 border-b border-slate-700 flex items-center justify-between">
                    <span className="text-sm text-slate-400">
                      {filteredVulnerabilities.length} из {vulnerabilities.length} уязвимостей
                    </span>
                    {(filterSeverity !== 'all' || filterCategory !== 'all') && (
                      <button
                        onClick={() => { setFilterSeverity('all'); setFilterCategory('all'); }}
                        className="text-xs text-emerald-400 hover:text-emerald-300"
                      >
                        Сбросить фильтры
                      </button>
                    )}
                  </div>
                  <div className="max-h-60 overflow-y-auto">
                    {filteredVulnerabilities.length === 0 ? (
                      <div className="p-6 text-center text-slate-500">
                        {vulnerabilities.length === 0 ? (
                          <div className="flex flex-col items-center gap-2">
                            <span className="text-3xl">✅</span>
                            <p>Уязвимостей не обнаружено!</p>
                          </div>
                        ) : (
                          <p>Нет уязвимостей с выбранными фильтрами</p>
                        )}
                      </div>
                    ) : (
                      filteredVulnerabilities.map((vuln, idx) => (
                        <button
                          key={idx}
                          onClick={() => setSelectedVuln(vuln)}
                          className={`w-full text-left p-3 border-b border-slate-700/50 hover:bg-slate-700/30 transition-all flex items-start gap-3 ${
                            selectedVuln?.id === vuln.id ? 'bg-slate-700/50' : ''
                          }`}
                        >
                          <span className="text-lg mt-0.5">{getSeverityIcon(vuln.severity)}</span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1 flex-wrap">
                              <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${getSeverityBadge(vuln.severity)}`}>
                                {vuln.severity.toUpperCase()}
                              </span>
                              {vuln.line && (
                                <span className="text-[10px] text-slate-500">Строка {vuln.line}</span>
                              )}
                              {vuln.evasionTechnique && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                  🎭 обход
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-slate-300 truncate">{vuln.title}</p>
                          </div>
                        </button>
                      ))
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Detail Panel */}
        {selectedVuln && hasScanned && (
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-8 animate-in">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <span className="text-2xl">{getSeverityIcon(selectedVuln.severity)}</span>
                <div>
                  <h3 className="text-lg font-semibold text-white">{selectedVuln.title}</h3>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${getSeverityBadge(selectedVuln.severity)}`}>
                      {selectedVuln.severity.toUpperCase()}
                    </span>
                    <span className="text-xs text-slate-500">{selectedVuln.category}</span>
                    {selectedVuln.line && (
                      <span className="text-xs text-slate-500">• Строка {selectedVuln.line}</span>
                    )}
                    {selectedVuln.evasionTechnique && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                        🎭 {selectedVuln.evasionTechnique}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="text-slate-400 hover:text-white transition-colors p-1"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div>
                  <h4 className="text-sm font-medium text-slate-400 mb-1">Описание</h4>
                  <p className="text-sm text-slate-300">{selectedVuln.description}</p>
                </div>
                {selectedVuln.code && (
                  <div>
                    <h4 className="text-sm font-medium text-slate-400 mb-1">Обнаруженный код</h4>
                    <code className="block text-xs bg-slate-900 border border-slate-700 rounded-lg p-3 text-red-400 font-mono overflow-x-auto">
                      {selectedVuln.code}
                    </code>
                  </div>
                )}
              </div>
              <div>
                <h4 className="text-sm font-medium text-emerald-400 mb-1">💡 Рекомендация</h4>
                <p className="text-sm text-slate-300 bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-3">
                  {selectedVuln.recommendation}
                </p>
                {selectedVuln.evasionTechnique && (
                  <div className="mt-3">
                    <h4 className="text-sm font-medium text-purple-400 mb-1">🎭 Техника обхода</h4>
                    <p className="text-sm text-slate-300 bg-purple-500/5 border border-purple-500/20 rounded-lg p-3">
                      Эта уязвимость использует технику обхода: <strong>{selectedVuln.evasionTechnique}</strong>.
                      Сканер v2.0 успешно её обнаружил благодаря расширенным правилам и эвристическому анализу.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Info Section */}
        {!hasScanned && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8">
            <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5">
              <div className="text-2xl mb-3">🔍</div>
              <h3 className="font-semibold text-slate-200 mb-2">Что проверяем</h3>
              <ul className="text-sm text-slate-400 space-y-1">
                <li>• SQL-инъекции (включая template literals)</li>
                <li>• XSS (innerHTML, insertAdjacentHTML...)</li>
                <li>• eval() и все его альтернативы</li>
                <li>• Хардкод секретов (Base64, XOR, char codes)</li>
                <li>• Командные инъекции</li>
                <li>• SSRF, Path Traversal, CORS</li>
              </ul>
            </div>
            <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5">
              <div className="text-2xl mb-3">🎭</div>
              <h3 className="font-semibold text-slate-200 mb-2">Обнаружение обходов</h3>
              <ul className="text-sm text-slate-400 space-y-1">
                <li>• Indirect eval: (0, eval)()</li>
                <li>• Bracket notation: window["eval"]</li>
                <li>• String concat: "ev"+"al"</li>
                <li>• Unicode escapes: \x65\x76...</li>
                <li>• Function constructor</li>
                <li>• Анализ энтропии строк</li>
                <li>• Паттерны обфускации</li>
              </ul>
            </div>
            <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5">
              <div className="text-2xl mb-3">⚡</div>
              <h3 className="font-semibold text-slate-200 mb-2">Как использовать</h3>
              <ol className="text-sm text-slate-400 space-y-1 list-decimal list-inside">
                <li>Вставьте код или загрузите файл</li>
                <li>Нажмите «Сканировать»</li>
                <li>Изучите найденные уязвимости</li>
                <li>Обратите внимание на техники обхода 🎭</li>
                <li>Исправьте все проблемы</li>
              </ol>
            </div>
          </div>
        )}

        {/* Sample Code Buttons */}
        {!hasScanned && !code && (
          <div className="flex flex-wrap justify-center gap-3 mt-8">
            <button
              onClick={loadEvasionExample}
              className="px-6 py-3 bg-purple-500/10 border border-purple-500/30 rounded-xl hover:bg-purple-500/20 transition-all text-sm text-purple-300 hover:text-purple-200 inline-flex items-center gap-2"
            >
              <span>🎭</span> Загрузить пример с обходами
            </button>
            <button
              onClick={() => {
                setCode(`// Простой уязвимый код
const express = require('express');
const app = express();

const DB_PASSWORD = "super_secret_123";

app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query, (err, results) => {
    res.send(results);
  });
});

app.post('/render', (req, res) => {
  document.write("<h1>" + req.body.title + "</h1>");
  eval(req.body.code);
});`);
                setFilename('simple-vulnerable.js');
              }}
              className="px-6 py-3 bg-slate-800 border border-slate-700 rounded-xl hover:bg-slate-700 hover:border-emerald-500/50 transition-all text-sm text-slate-400 hover:text-emerald-400 inline-flex items-center gap-2"
            >
              <span>🧪</span> Простой пример уязвимостей
            </button>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-700/50 mt-16 py-6">
        <div className="max-w-7xl mx-auto px-4 text-center text-sm text-slate-500">
          <p>VulnScanner v2.0 — инструмент статического анализа безопасности с обнаружением обходов</p>
          <p className="mt-1 text-xs text-slate-600">
            ⚠️ Это инструмент для образовательных целей. Для полного аудита безопасности используйте профессиональные решения (Snyk, SonarQube, Checkmarx).
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
