import { Vulnerability } from './vulnerabilityRules';

interface MobileRule {
  pattern: RegExp;
  title: string;
  severity: Vulnerability['severity'];
  description: string;
  recommendation: string;
  category: string;
  fileType: 'smali' | 'manifest' | 'xml' | 'plist' | 'mobile-code';
}

export const mobileRules: MobileRule[] = [
  // ============================================
  // AndroidManifest.xml Analysis
  // ============================================
  {
    pattern: /android:exported\s*=\s*["']true["']/gi,
    title: 'Exported компонент доступен извне',
    severity: 'high',
    description: 'Компонент (Activity/Service/Receiver) экспортирован и доступен другим приложениям без ограничений.',
    recommendation: 'Добавьте android:permission для ограничения доступа или установите exported=false если компонент не нужен извне.',
    category: 'Android Manifest',
    fileType: 'manifest',
  },
  {
    pattern: /android:allowBackup\s*=\s*["']true["']/gi,
    title: 'Разрешено резервное копирование приложения',
    severity: 'medium',
    description: 'allowBackup=true позволяет извлекать данные приложения через adb backup.',
    recommendation: 'Установите android:allowBackup="false" в AndroidManifest.xml.',
    category: 'Android Manifest',
    fileType: 'manifest',
  },
  {
    pattern: /android:debuggable\s*=\s*["']true["']/gi,
    title: 'Приложение в режиме отладки',
    severity: 'critical',
    description: 'debuggable=true в production позволяет подключать отладчик и извлекать данные.',
    recommendation: 'Удалите android:debuggable или установите false для release-сборки.',
    category: 'Android Manifest',
    fileType: 'manifest',
  },
  {
    pattern: /android:testOnly\s*=\s*["']true["']/gi,
    title: 'Приложение помечено как тестовое',
    severity: 'high',
    description: 'testOnly=true означает, что APK собран для тестирования и может содержать уязвимости.',
    recommendation: 'Соберите release-версию без флага testOnly.',
    category: 'Android Manifest',
    fileType: 'manifest',
  },
  {
    pattern: /android:usesCleartextTraffic\s*=\s*["']true["']/gi,
    title: 'Разрешён cleartext (HTTP) трафик',
    severity: 'high',
    description: 'Приложение разрешает незашифрованные HTTP-соединения, данные передаются в открытом виде.',
    recommendation: 'Используйте HTTPS. Установите android:usesCleartextTraffic="false".',
    category: 'Network Security',
    fileType: 'manifest',
  },
  {
    pattern: /android:networkSecurityConfig/gi,
    title: 'Используется Network Security Config',
    severity: 'info',
    description: 'Обнаружена ссылка на Network Security Config. Проверьте его содержимое.',
    recommendation: 'Убедитесь, что network_security_config.xml не разрешает cleartext и доверяет только надёжным CA.',
    category: 'Network Security',
    fileType: 'manifest',
  },

  // Dangerous Permissions
  {
    pattern: /android\.permission\.(?:READ_CONTACTS|WRITE_CONTACTS|READ_CALL_LOG|WRITE_CALL_LOG|READ_SMS|SEND_SMS|RECEIVE_SMS|READ_PHONE_STATE|CALL_PHONE|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE)/g,
    title: 'Dangerous permission запрашивается',
    severity: 'medium',
    description: 'Приложение запрашивает опасное разрешение, требующее явного согласия пользователя.',
    recommendation: 'Запрашивайте разрешения только при необходимости. Используйте runtime permissions (Android 6.0+).',
    category: 'Permissions',
    fileType: 'manifest',
  },
  {
    pattern: /android\.permission\.(?:INSTALL_PACKAGES|SYSTEM_ALERT_WINDOW|WRITE_SETTINGS|REQUEST_INSTALL_PACKAGES|BIND_ACCESSIBILITY_SERVICE|BIND_DEVICE_ADMIN|READ_LOGS|DUMP)/g,
    title: 'Критическое системное разрешение',
    severity: 'high',
    description: 'Приложение запрашивает разрешение с повышенными привилегиями.',
    recommendation: 'Обоснуйте необходимость этого разрешения. Многие из них не должны использоваться обычными приложениями.',
    category: 'Permissions',
    fileType: 'manifest',
  },
  {
    pattern: /android\.permission\.INTERNET/g,
    title: 'Разрешение на доступ в интернет',
    severity: 'info',
    description: 'Приложение имеет доступ к интернету.',
    recommendation: 'Убедитесь, что сетевые запросы идут только на доверенные серверы по HTTPS.',
    category: 'Permissions',
    fileType: 'manifest',
  },

  // Intent Filters
  {
    pattern: /<intent-filter[^>]*>[\s\S]*?<action\s+android:name\s*=\s*["']android\.intent\.action\.VIEW["']/gi,
    title: 'Deep Link / Intent Filter для VIEW',
    severity: 'medium',
    description: 'Компонент обрабатывает VIEW intent — возможен deep link hijacking.',
    recommendation: 'Используйте android:autoVerify="true" для App Links. Валидируйте входящие данные.',
    category: 'Intent Security',
    fileType: 'manifest',
  },

  // ============================================
  // Smali Code Analysis
  // ============================================
  {
    pattern: /const-string\s+\w+,\s*["'](?:https?:\/\/|ftp:\/\/)/gi,
    title: 'URL в smali-коде',
    severity: 'info',
    description: 'Обнаружен URL в smali-коде. Проверьте, не ведёт ли он на подозрительный сервер.',
    recommendation: 'Используйте HTTPS. Проверьте домен на принадлежность к доверенным.',
    category: 'Smali Analysis',
    fileType: 'smali',
  },
  {
    pattern: /const-string\s+\w+,\s*["'][A-Za-z0-9+\/=]{20,}["']/g,
    title: 'Потенциальный Base64-ключ в smali',
    severity: 'high',
    description: 'Обнаружена длинная Base64-подобная строка — возможен захардкоженный ключ или токен.',
    recommendation: 'Не храните ключи в коде. Используйте Android Keystore или серверное хранение.',
    category: 'Hardcoded Secrets',
    fileType: 'smali',
  },
  {
    pattern: /Ljavax\/crypto\/spec\/SecretKeySpec;-><init>\s*\(\s*\[B/g,
    title: 'Создание криптографического ключа',
    severity: 'medium',
    description: 'Обнаружено создание SecretKeySpec — проверьте, откуда берутся байты ключа.',
    recommendation: 'Используйте Android Keystore для хранения ключей. Не генерируйте ключи из констант.',
    category: 'Cryptography',
    fileType: 'smali',
  },
  {
    pattern: /Ljava\/security\/MessageDigest;->getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']/gi,
    title: 'Слабый хеш-алгоритм в smali',
    severity: 'medium',
    description: 'Используется MD5 или SHA-1 — криптографически небезопасные алгоритмы.',
    recommendation: 'Используйте SHA-256 или SHA-3. Для паролей — bcrypt/scrypt/argon2.',
    category: 'Weak Cryptography',
    fileType: 'smali',
  },
  {
    pattern: /Landroid\/webkit\/WebView;->setJavaScriptEnabled\s*\(\s*1\)/g,
    title: 'JavaScript включен в WebView',
    severity: 'high',
    description: 'WebView с включенным JavaScript уязвим к XSS, если загружает непроверенный контент.',
    recommendation: 'Отключите JavaScript если не нужен. Используйте @JavascriptInterface с осторожностью.',
    category: 'WebView Security',
    fileType: 'smali',
  },
  {
    pattern: /Landroid\/webkit\/WebView;->addJavascriptInterface/g,
    title: 'JavascriptInterface добавлен в WebView',
    severity: 'critical',
    description: 'addJavascriptInterface создаёт мост между JS и Java — уязвимость на Android < 4.2.',
    recommendation: 'Используйте только на Android 4.2+. Аннотируйте методы @JavascriptInterface. Валидируйте вход.',
    category: 'WebView Security',
    fileType: 'smali',
  },
  {
    pattern: /Landroid\/webkit\/WebView;->setWebContentsDebuggingEnabled\s*\(\s*1\)/g,
    title: 'WebView debugging включен',
    severity: 'high',
    description: 'WebContentsDebugging позволяет подключать Chrome DevTools к WebView.',
    recommendation: 'Отключите в production: WebView.setWebContentsDebuggingEnabled(false).',
    category: 'WebView Security',
    fileType: 'smali',
  },
  {
    pattern: /loadUrl\s*\(\s*["'](?:javascript:|data:)/gi,
    title: 'WebView загружает javascript:/data: URL',
    severity: 'critical',
    description: 'Загрузка javascript: или data: URL в WebView — прямой путь к XSS.',
    recommendation: 'Используйте shouldOverrideUrlLoading для фильтрации URL. Запретите javascript: scheme.',
    category: 'WebView Security',
    fileType: 'smali',
  },
  {
    pattern: /Landroid\/content\/SharedPreferences;->edit/g,
    title: 'Запись в SharedPreferences',
    severity: 'info',
    description: 'SharedPreferences хранит данные в открытом виде (XML-файл).',
    recommendation: 'Не храните секреты в SharedPreferences. Используйте EncryptedSharedPreferences или Android Keystore.',
    category: 'Data Storage',
    fileType: 'smali',
  },
  {
    pattern: /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/g,
    title: 'Файл доступен другим приложениям',
    severity: 'critical',
    description: 'MODE_WORLD_READABLE/WRITEABLE делает файл доступным всем приложениям на устройстве.',
    recommendation: 'Используйте MODE_PRIVATE. Данные не должны быть доступны другим приложениям.',
    category: 'Data Storage',
    fileType: 'smali',
  },
  {
    pattern: /Landroid\/net\/Uri;->parse\s*\(\s*\w+/g,
    title: 'Динамический Uri.parse()',
    severity: 'medium',
    description: 'Uri.parse() с переменной — возможен URI hijacking или deep link abuse.',
    recommendation: 'Валидируйте схему, хост и путь. Используйте whitelist доверенных доменов.',
    category: 'Intent Security',
    fileType: 'smali',
  },
  {
    pattern: /Landroid\/content\/Intent;->setClass|startActivity\s*\(\s*\w+/g,
    title: 'Динамический запуск Activity',
    severity: 'medium',
    description: 'Динамический запуск компонентов — возможен intent hijacking.',
    recommendation: 'Используйте явные intents. Проверяйте package name целевого компонента.',
    category: 'Intent Security',
    fileType: 'smali',
  },
  {
    pattern: /Landroid\/telephony\/TelephonyManager;->getDeviceId|getImei|getMeid/g,
    title: 'Чтение идентификатора устройства',
    severity: 'medium',
    description: 'Получение IMEI/MEID — нарушение приватности, запрещено на Android 10+.',
    recommendation: 'Используйте getInstanceId() или UUID для идентификации. Не собирайте IMEI.',
    category: 'Privacy',
    fileType: 'smali',
  },
  {
    pattern: /Landroid\/provider\/Settings\$Secure;->getString.*android_id/g,
    title: 'Чтение Android ID',
    severity: 'low',
    description: 'Android ID может быть сброшен и не является надёжным идентификатором.',
    recommendation: 'Используйте getInstanceId() для надёжной идентификации установки.',
    category: 'Privacy',
    fileType: 'smali',
  },

  // ============================================
  // iOS Plist Analysis
  // ============================================
  {
    pattern: /NSAppTransportSecurity[\s\S]*?NSAllowsArbitraryLoads\s*<true\/>/gi,
    title: 'ATS отключен (iOS)',
    severity: 'high',
    description: 'App Transport Security отключен — разрешены HTTP-соединения.',
    recommendation: 'Используйте HTTPS. Если нужен exception, укажите конкретные домены в NSExceptionDomains.',
    category: 'iOS Security',
    fileType: 'plist',
  },
  {
    pattern: /UIFileSharingEnabled\s*<true\/>|UISupportsDocumentBrowser\s*<true\/>/gi,
    title: 'File Sharing включен (iOS)',
    severity: 'medium',
    description: 'Приложение разрешает обмен файлами — данные могут быть доступны через iTunes/Finder.',
    recommendation: 'Отключите file sharing если не требуется. Используйте UIDocumentPickerViewController.',
    category: 'iOS Security',
    fileType: 'plist',
  },
  {
    pattern: /UIRequiresPersistentWiFi\s*<true\/>/gi,
    title: 'Persistent WiFi (iOS)',
    severity: 'info',
    description: 'Приложение требует постоянного WiFi-соединения — повышенный расход батареи.',
    recommendation: 'Убедитесь, что это действительно необходимо. Используйте background fetch.',
    category: 'iOS Security',
    fileType: 'plist',
  },
  {
    pattern: /NSLocationAlwaysUsageDescription|NSLocationAlwaysAndWhenInUseUsageDescription/gi,
    title: 'Фоновое отслеживание геолокации (iOS)',
    severity: 'medium',
    description: 'Приложение запрашивает постоянный доступ к геолокации.',
    recommendation: 'Обоснуйте необходимость. Используйте WhenInUse если фоновое отслеживание не нужно.',
    category: 'Privacy',
    fileType: 'plist',
  },

  // ============================================
  // Mobile Code Patterns (React Native, Flutter, etc.)
  // ============================================
  {
    pattern: /AsyncStorage\.(?:setItem|getItem)\s*\(\s*["'](?:token|password|secret|key|auth)/gi,
    title: 'Секреты в AsyncStorage (React Native)',
    severity: 'high',
    description: 'Токены/пароли хранятся в AsyncStorage — не зашифрованы.',
    recommendation: 'Используйте react-native-keychain или expo-secure-store для хранения секретов.',
    category: 'Data Storage',
    fileType: 'mobile-code',
  },
  {
    pattern: /Linking\.openURL\s*\(\s*(?:url|link|href|uri)/gi,
    title: 'Открытие URL без валидации (React Native)',
    severity: 'medium',
    description: 'Linking.openURL() с динамическим URL — возможен deep link abuse.',
    recommendation: 'Валидируйте URL перед открытием. Используйте whitelist разрешённых схем и доменов.',
    category: 'Intent Security',
    fileType: 'mobile-code',
  },
  {
    pattern: /<WebView[^>]*(?:javaScriptEnabled|domStorageEnabled)\s*=\s*\{\s*true/gi,
    title: 'WebView с включенным JS (React Native)',
    severity: 'high',
    description: 'React Native WebView с JavaScript — возможен XSS при загрузке непроверенного контента.',
    recommendation: 'Используйте onShouldStartLoadWithRequest для фильтрации. Отключите JS если не нужен.',
    category: 'WebView Security',
    fileType: 'mobile-code',
  },
  {
    pattern: /Keychain\.setGenericPassword|Keychain\.getInternetCredentials/g,
    title: 'Использование Keychain (iOS/React Native)',
    severity: 'info',
    description: 'Обнаружено использование Keychain — правильное хранение секретов.',
    recommendation: 'Убедитесь, что используется kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly или строже.',
    category: 'Data Storage',
    fileType: 'mobile-code',
  },
  {
    pattern: /SSL_PINNING|sslPinning|certificatePinning/gi,
    title: 'SSL Pinning обнаружен',
    severity: 'info',
    description: 'Приложение использует SSL pinning — защита от MITM.',
    recommendation: 'Реализуйте backup pins для ротации сертификатов. Используйте SPKI pinning.',
    category: 'Network Security',
    fileType: 'mobile-code',
  },
  {
    pattern: /(?:jailbreak|root|cydia|substrate|magisk)/gi,
    title: 'Обнаружение root/jailbreak',
    severity: 'info',
    description: 'Приложение проверяет наличие root/jailbreak.',
    recommendation: 'Root detection легко обходится. Используйте его как дополнительный слой, не как единственный.',
    category: 'Anti-Tampering',
    fileType: 'mobile-code',
  },
];

export function analyzeMobileCode(code: string, fileType: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = code.split('\n');

  // Determine file type if not specified
  let detectedType = fileType;
  if (!detectedType) {
    if (code.includes('.class') && code.includes('->')) detectedType = 'smali';
    else if (code.includes('<manifest') || code.includes('<activity')) detectedType = 'manifest';
    else if (code.includes('<?xml') && code.includes('<plist')) detectedType = 'plist';
    else detectedType = 'mobile-code';
  }

  for (const rule of mobileRules) {
    // Filter rules by file type
    if (rule.fileType !== detectedType && rule.fileType !== 'mobile-code') continue;

    const matches = code.matchAll(new RegExp(rule.pattern));
    for (const match of matches) {
      const index = match.index!;
      const lineNum = code.substring(0, index).split('\n').length;
      const lineContent = lines[lineNum - 1]?.trim() || '';

      vulnerabilities.push({
        id: `MOBILE-${vulnerabilities.length + 1}`,
        title: rule.title,
        severity: rule.severity,
        description: rule.description,
        line: lineNum,
        code: lineContent.length > 120 ? lineContent.substring(0, 120) + '...' : lineContent,
        recommendation: rule.recommendation,
        category: rule.category,
      });
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Re-assign IDs
  vulnerabilities.forEach((v, i) => { v.id = `MOBILE-${i + 1}`; });

  return vulnerabilities;
}
