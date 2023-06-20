using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;

namespace APSoft_WebScanner
{
    public class newHelper
    {
        #region Locals

        public int inheritance = 0;
        public List<modBase> searchersList = new List<modBase>();
        public List<string> urlsList = new List<string>();
        public List<string> vulnerAblesList = new List<string>();
        public MainWindow mainFormObject { get; set; }
        private Action<string, object> logger { get; set; }
        public string ownerName { get; set; }
        public string ownerId { get; set; }
        public string ownerMail { get; set; }
        public string ownerCode { get; set; }
        private bool loggerInvoke { get; set; }
        private string resultPath { get; set; }
        public string softwareName { get; set; }
        public string captchaSolvingToken { get; set; }
        public string capmonsterDefult { get; set; }
        public string softwareMod { get; set; }
        public List<string> combolist = new List<string>();
        public List<string> proxyList = new List<string>();
        public List<string> errorList = new List<string>();
        public string proxyType { get; set; }
        public string proxyUrl { get; set; }
        public int proxyAutoUpdate { get; set; }
        private readonly object locker = new object();
        public bool debugMod = false;
        public bool working = false;
        public bool loadByFile = false;
        public List<Thread> threadlist = new List<Thread>();
        public List<modBase> softwareMods = new List<modBase>();
        public int CheckingThreads = 0;
        private const int threadsLimit = 400;
        public int threadsActive = 0;
        public int timeOut = 0;
        private readonly Stopwatch timer = new Stopwatch();
        private readonly List<List<string>> listLists = new List<List<string>>();
        public List<string> userAgentList = new List<string>();
        public bool autoUpdateProxy = false;

        public string searcherMod = "";
        public string bugsMod = "";
        private readonly ReaderWriterLockSlim _readWriteLock = new ReaderWriterLockSlim();

        #endregion Locals

        public List<string> insertPayload(string url, string payLoad)
        {
            List<string> result = new List<string>();
            if (url.Contains("?") && url.Contains("="))
            {
                if (url.Contains("&"))
                {
                    string noTouch = url.Split('?')[0];
                    string[] parameters = url.Split('?')[1].Split('&');
                    for (int i = 0; i < parameters.Length; i++)
                    {
                        string paraMeterValue = parameters[i].Split('=')[1];
                        string newUrl = url.Replace(paraMeterValue, paraMeterValue + payLoad);
                        result.Add(newUrl);
                    }
                }
                else
                {
                    string paraMeterValue = url.Split('=')[1].ToString();
                    result.Add(url.Replace(paraMeterValue, paraMeterValue + payLoad));
                }
            }
            else
            {
                result.Add("itsnotInjectAble");
            }
            return result;
        }

        public void addLog(string text, object dataTwo = null)
        {
            try
            {
                text = "[" + DateTime.Now.ToString("G") + "] - " + text + "";
                if (dataTwo != null)
                {
                    logger(text, dataTwo);
                }
                else
                {
                    logger(text, null);
                }
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void createResultPath()
        {
            try
            {
                string name = DateTime.Now.ToString("g");
                name = name.Replace("/", "-").Replace(":", "-");
                if (!Directory.Exists($"Result-{softwareName}"))
                {
                    Directory.CreateDirectory($"Result-{softwareName}");
                }
                if (!Directory.Exists($@"Result-{softwareName}\{name}"))
                {
                    Directory.CreateDirectory($@"Result-{softwareName}\{name}");
                }
                resultPath = $@"Result-{softwareName}\{name}";
                if (debugMod)
                {
                    addLog(resultPath);
                }
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void listClearance(ref List<string> target)
        {
            try
            {
                Stopwatch st = new Stopwatch();
                st.Start();
                List<string> temp = new List<string>();
                int totalCount = target.Count;
                int cleanedCount = 0;
                IEnumerable<string> list2 = target.Distinct();
                cleanedCount = list2.Count();
                temp.AddRange(list2);
                int count = temp.Count;
                target = new List<string>();

                target.AddRange(list2);

                cleanedCount = target.Count;

                st.Stop();
                if (target != proxyList)

                {
                    addLog($"Source count : {totalCount} , Cleanaed count : {cleanedCount}, Time : {Math.Round(st.Elapsed.TotalSeconds)} s");
                }
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void loadList(string path, ref List<string> target)
        {
            try
            {
                using (StreamReader st = File.OpenText(path))
                {
                    string line = "";
                    while ((line = st.ReadLine()) != null)
                    {
                        target.Add(line);
                    }
                }
                string name = "";
                if (target == proxyList)
                {
                    name = "proxylist";
                    statistics.Proxies = target.Count;
                    statistics.Proxies_FX += target.Count;
                }
                else
                {
                    name = "undefinedlist";
                }
                addLog($"Loaded list count : {target.Count} , Target : {name}");
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void Save(string data, string type)
        {
            _readWriteLock.EnterWriteLock();
            try
            {
                if (resultPath.Length < 10)
                {
                    createResultPath();
                }
                if (!Directory.Exists($@"{resultPath}\{softwareMod}"))
                {
                    Directory.CreateDirectory($@"{resultPath}\{softwareMod}");
                }
                string fileNM = $@"{resultPath}\{softwareMod}\{type}.txt";
                using (StreamWriter st = File.AppendText(fileNM))
                {
                    st.WriteLine(data);
                }
            }
            finally
            {
                _readWriteLock.ExitWriteLock();
            }
        }

        public void HandleException(Exception E)
        {
            if (debugMod)
            {
                StackTrace trace = new StackTrace(E, true);
                string data = trace.GetFrame(0).GetFileLineNumber().ToString() + ": " + E.Message;
                if (!errorList.Contains(data))
                {
                    errorList.Add(data);
                    addLog(data);
                    Save(data, "Error");
                }
            }
        }

        public string getProxy(bool rem)
        {
            try
            {
                if (proxyList.Count > 0)
                {
                    string now = "";

                    if (rem)
                    {
                        Random r = new Random();
                        now = proxyList[r.Next(0, proxyList.Count - 1)];
                    }
                    else
                    {
                        lock (locker)
                        {
                            now = proxyList[0];
                            proxyList.RemoveAt(0);
                        }
                    }
                    if (now.Length > 4)
                    {
                        return now;
                    }
                    else
                    {
                        return "wait";
                    }
                }
                else
                {
                    return "wait";
                }
            }
            catch (Exception E)
            {
                HandleException(E);
                return "wait";
            }
        }

        public string getUserAgent()
        {
            try
            {
                if (userAgentList.Count > 0)
                {
                    string now = "";

                    Random r = new Random();
                    now = userAgentList[r.Next(0, userAgentList.Count - 1)];
                    if (now.Length > 4)
                    {
                        return now;
                    }
                    else
                    {
                        return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15";
                    }
                }
                else
                {
                    return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15";
                }
            }
            catch (Exception E)
            {
                HandleException(E);
                return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15";
            }
        }

        public void setProxy(ref Leaf.xNet.HttpRequest req, string proxy)
        {
            try
            {
                proxyType = proxyType.Replace(" ", "").ToLower();
                if (proxyType == "socks4")
                {
                    req.Proxy = Leaf.xNet.ProxyClient.Parse(Leaf.xNet.ProxyType.Socks4, proxy);
                }
                else if (proxyType == "socks5")
                {
                    req.Proxy = Leaf.xNet.ProxyClient.Parse(Leaf.xNet.ProxyType.Socks5, proxy);
                }
                else if (proxyType == "http")
                {
                    req.Proxy = Leaf.xNet.ProxyClient.Parse(Leaf.xNet.ProxyType.HTTP, proxy);
                }
                else
                {
                    if (debugMod)
                    {
                        addLog($"Proxy type is not valid , its {proxyType} now");
                    }
                }
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void saveComboRemain(bool itsFinal)
        {
            try
            {
                if (!itsFinal)
                {
                    lock (locker)
                    {
                        List<string> datas = new List<string>();
                        foreach (var item in listLists)
                        {
                            datas.AddRange(item);
                        }
                        string path = $@"{resultPath}\{softwareMod}\UncheckedCombolist.txt";
                        File.WriteAllLines(path, datas);
                        if (debugMod)
                        {
                            addLog($"We saved {datas.Count} lines , uncehcked combolist");
                        }
                    }
                }
                else
                {
                    lock (locker)
                    {
                        string path = $@"{resultPath}\{softwareMod}\UncheckedCombolist.txt";
                        if (File.Exists(path))
                        {
                            File.Delete(path);
                            if (debugMod)
                            {
                                addLog("Unchecked file removed because of non working");
                            }
                        }
                        else
                        {
                            if (debugMod)
                            {
                                addLog("Unchecked file does not exists");
                            }
                        }
                    }
                }
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void loadProxyByUrl(bool withThread, int updateInterval = 15)
        {
            try
            {
                if (withThread)
                {
                    Thread a = new Thread(new ThreadStart(() =>
                    {
                        while (true)
                        {
                            again:
                            try
                            {
                                if (loadByFile)
                                {
                                    proxyList.Clear();
                                    loadList(proxyUrl, ref proxyList);
                                }
                                else
                                {
                                    xNet.HttpRequest req = new xNet.HttpRequest
                                    {
                                        IgnoreProtocolErrors = true,
                                        Cookies = new xNet.CookieDictionary(false),
                                        KeepAlive = true,
                                        ConnectTimeout = 20000,
                                        ReadWriteTimeout = 20000
                                    };
                                    req.Get(proxyUrl, null);
                                    string source = req.Response.ToString();
                                    if (source.Length > 50)
                                    {
                                        Regex rx = new Regex(@"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5}");
                                        MatchCollection collection = rx.Matches(source);
                                        if (collection.Count > 30)
                                        {
                                            proxyList.Clear();
                                            foreach (Match item in collection)
                                            {
                                                try
                                                {
                                                    string value = item.Value.ToString();
                                                    if (value.Length > 10)
                                                    {
                                                        proxyList.Add(value);
                                                    }
                                                    else
                                                    {
                                                        continue;
                                                    }
                                                }
                                                catch { }
                                            }
                                            listClearance(ref proxyList);
                                            statistics.Proxies = proxyList.Count;
                                            statistics.Proxies_FX += proxyList.Count;
                                            addLog($"{proxyList.Count} proxies updated", ConsoleColor.Cyan);
                                        }
                                        else
                                        {
                                            addLog("There is no enough proxies in pool", ConsoleColor.Red);
                                        }
                                    }
                                    else
                                    {
                                        addLog("There is no proxies in pool", ConsoleColor.Red);
                                    }
                                }
                            }
                            catch (Exception E)
                            {
                                HandleException(E);

                                Thread.Sleep(5000);
                                goto again;
                            }
                            Thread.Sleep(updateInterval * 60000);
                        }
                    }));
                    threadlist.Add(a);
                    a.Start();
                }
                else
                {
                    try
                    {
                        xNet.HttpRequest req = new xNet.HttpRequest
                        {
                            IgnoreProtocolErrors = true,
                            Cookies = new xNet.CookieDictionary(false),
                            KeepAlive = true,
                            ConnectTimeout = 20000,
                            ReadWriteTimeout = 20000
                        };
                        req.Get(proxyUrl, null);
                        string source = req.Response.ToString();
                        if (source.Length > 50)
                        {
                            Regex rx = new Regex(@"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5}");
                            MatchCollection collection = rx.Matches(source);
                            if (collection.Count > 30)
                            {
                                proxyList.Clear();
                                foreach (Match item in collection)
                                {
                                    try
                                    {
                                        string value = item.Value.ToString();
                                        if (value.Length > 10)
                                        {
                                            proxyList.Add(value);
                                        }
                                        else
                                        {
                                            continue;
                                        }
                                    }
                                    catch { }
                                }
                                listClearance(ref proxyList);
                                statistics.Proxies = proxyList.Count;
                                statistics.Proxies_FX += proxyList.Count;
                                addLog($"{proxyList.Count} proxies updated", ConsoleColor.Cyan);
                            }
                            else
                            {
                                addLog("There is no enough proxies in pool", ConsoleColor.Red);
                            }
                        }
                        else
                        {
                            addLog("There is no proxies in pool", ConsoleColor.Red);
                        }
                    }
                    catch (Exception E)
                    {
                        HandleException(E);
                    }
                }
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public delegate bruteResult CONFIGER(ref string dork, string objectString, string proxy = null, string additionalOne = null, string additionalTwo = null);

        public void Starter(List<string> target, modBase mod, bool saveit, bool needProxy, Func<bool> CANUSE, CONFIGER CONFIG, bool needCaptcha, bool saveExpectHit = false)
        {
            threadsActive++;
            try
            {
                int count = target.Count;
                for (int i = 0; i < count; i++)
                {
                    try
                    {
                        var current = target[0];
                        if (current.Length > 3)
                        {
                            string proxy = "";
                            if (needProxy)
                            {
                                if (autoUpdateProxy)
                                {
                                    proxy = getProxy(true);
                                }
                                else
                                {
                                    proxy = getProxy(false);
                                }
                                if (proxy == "wait")
                                {
                                    Thread.Sleep(2000);
                                    continue;
                                }
                            }
                            bruteResult result = CONFIG(ref current, "", proxy, null, null);
                            if (result == bruteResult.bing)
                            {
                                target.RemoveAt(0);
                                Interlocked.Increment(ref statistics.urlFound);
                                Interlocked.Increment(ref statistics.bing);
                                showStatusVoid();
                                continue;
                            }
                            else if (result == bruteResult.google)
                            {
                                target.RemoveAt(0);
                                Interlocked.Increment(ref statistics.urlFound);
                                Interlocked.Increment(ref statistics.google);
                                showStatusVoid();
                                continue;
                            }
                            else if (result == bruteResult.sql)
                            {
                                target.RemoveAt(0);
                                Interlocked.Increment(ref statistics.sql);
                                showStatusVoid();
                                string waf = Regex.Match(current, "WAF=(.*?) ").Groups[1].Value.ToString();
                                Save(current, "sql-Waf = " + waf);
                                continue;
                            }
                            else if (result == bruteResult.xss)
                            {
                                target.RemoveAt(0);
                                Interlocked.Increment(ref statistics.xss);
                                showStatusVoid();
                                string waf = Regex.Match(current, "WAF=(.*?) ").Groups[1].Value.ToString();
                                Save(current, "xss-Waf = " + waf);
                                continue;
                            }
                            else if (result == bruteResult.sqlXss)
                            {
                                target.RemoveAt(0);
                                Interlocked.Increment(ref statistics.xss);
                                Interlocked.Increment(ref statistics.sql);
                                showStatusVoid();
                                string waf = Regex.Match(current.Split('*')[0], "WAF=(.*?) ").Groups[1].Value.ToString();
                                Save(current.Split('*')[0], "sql-Waf = " + waf);
                                waf = Regex.Match(current.Split('*')[1], "WAF=(.*?) ").Groups[1].Value.ToString();
                                Save(current.Split('*')[1], "xss-Waf = " + waf);
                                continue;
                            }
                            else if (result == bruteResult.unvulnerAble)
                            {
                                target.RemoveAt(0);
                                Save(current, "unvulnerAble");
                                Interlocked.Increment(ref statistics.unvulnerAble);
                                showStatusVoid();
                                continue;
                            }
                            else if (result == bruteResult.retry)
                            {
                                target.Add(current);
                                target.RemoveAt(0);
                                Interlocked.Increment(ref statistics.Retries);
                                showStatusVoid();
                                continue;
                            }
                            else if (result == bruteResult.itsSearcher)
                            {
                                target.RemoveAt(0);
                                Interlocked.Increment(ref statistics.dorksChecked);
                                showStatusVoid();
                                continue;
                            }
                            else
                            {
                                Interlocked.Increment(ref statistics.errors);
                                showStatusVoid();
                                continue;
                            }
                        }
                        else
                        {
                            target.RemoveAt(0);
                            Interlocked.Increment(ref statistics.unvulnerAble);
                            showStatusVoid();
                            continue;
                        }
                    }
                    catch (Exception E)
                    {
                        HandleException(E);
                    }
                }
                threadsActive--;
            }
            catch (Exception E)
            {
                threadsActive--;
                HandleException(E);
            }
        }

        public void startTimer()
        {
            try
            {
                Thread th = new Thread(new ThreadStart(() =>
                {
                    timer.Start();
                    while (true)
                    {
                        if (!working)
                        {
                            timer.Stop();
                            break;
                        }
                        string data = string.Format("{0:00} : {1:00} : {2:00}", timer.Elapsed.Hours, timer.Elapsed.Minutes, timer.Elapsed.Seconds);
                        mainFormObject.Dispatcher.Invoke(() =>
                        {
                            mainFormObject.elapsedTimeLabel.Content = data;
                        });
                        Thread.Sleep(1000);
                    }
                }))
                {
                    IsBackground = true
                };
                threadlist.Add(th);
                th.Start();
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void showStatusVoid()
        {
            try
            {
                mainFormObject.Dispatcher.Invoke(() =>
                {
                    mainFormObject.urlFoundLabel.Content = statistics.urlFound.ToString();
                    mainFormObject.vulnerAbleLabel.Content = statistics.unvulnerAble.ToString();
                    mainFormObject.bingLabel.Content = statistics.bing.ToString();
                    mainFormObject.googleLabel.Content = statistics.google.ToString();
                    mainFormObject.xssLabel.Content = statistics.xss.ToString();
                    mainFormObject.sqlLabel.Content = statistics.sql.ToString();
                    mainFormObject.dorkCheckedLabel.Content = statistics.dorksChecked.ToString();
                });
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void Start(List<string> targetList, bool checkBugs = false)
        {
            try
            {
                if (checkBugs == false)
                {
                    listLists.Clear();
                    searchersList.Add(new allSearcher(this, autoUpdateProxy) { UseAble = true });
                    searchersList.Add(new bingSearcher(this, autoUpdateProxy) { UseAble = true });
                    searchersList.Add(new googleSearcher(this, autoUpdateProxy) { UseAble = true });
                    searcherMod = searcherMod.ToLower();
                    if (string.IsNullOrEmpty(searcherMod))
                    {
                        addLog("Select a valid mod first to use software");
                        return;
                    }
                    else
                    {
                        var selectedMod = searchersList.FirstOrDefault(func => func.Name.ToLower() == searcherMod);
                        if (selectedMod == null)
                        {
                            addLog("Selected mod doesent exists", "Error");
                            return;
                        }
                        else
                        {
                            if (selectedMod.UseAble == false)
                            {
                                addLog("Selected mod is not useable at this moment", "Error");
                                return;
                            }
                            else
                            {
                                working = true;
                                if (selectedMod.CanUse())
                                {
                                    if (selectedMod.NeedProxy)
                                    {
                                        loadProxyByUrl(false, proxyAutoUpdate);

                                        if (autoUpdateProxy)
                                        {
                                            loadProxyByUrl(true, proxyAutoUpdate);
                                        }
                                    }
                                    threadLimiter();

                                    #region separateList

                                    int diff = targetList.Count % CheckingThreads;
                                    int totalPerFile = (targetList.Count - diff) / CheckingThreads;
                                    int ineed = 0;
                                    List<string> test = new List<string>();
                                    int count = targetList.Count;
                                    int currentIndex = 0;
                                    while (true)
                                    {
                                        if (ineed + 1 == CheckingThreads)
                                        {
                                            ineed++;
                                            addLog($"All threads are activated now , we have {ineed} now");
                                            test = targetList.GetRange(currentIndex, targetList.Count - currentIndex);
                                            listLists.Add(new List<string>(test));
                                            test.Clear();
                                            break;
                                        }
                                        else
                                        {
                                            test = targetList.GetRange(currentIndex, totalPerFile);
                                            listLists.Add(new List<string>(test));
                                            test.Clear();
                                            ineed++;
                                            currentIndex += totalPerFile;
                                        }
                                    }

                                    if (debugMod)
                                    {
                                        addLog($"List : {targetList.Count}, Per list : {totalPerFile}, Ineed : {ineed}");
                                    }
                                    foreach (var item in listLists)
                                    {
                                        Thread th2 = new Thread(new ThreadStart(() =>
                                        {
                                            Starter(item, selectedMod, true, selectedMod.NeedProxy, selectedMod.CanUse, selectedMod.Config, selectedMod.NeedCaptcha, true);
                                        }))
                                        {
                                            IsBackground = true
                                        };
                                        threadlist.Add(th2);
                                        th2.Start();
                                    }
                                    Thread th = new Thread(new ThreadStart(() =>
                                    {
                                        while (true)
                                        {
                                            Thread.Sleep(10000);
                                            if (threadsActive <= 0 && selectedMod.transActions <= 0)

                                            {
                                                mainFormObject.Dispatcher.Invoke(() =>
                                                {
                                                    mainFormObject.Button_Click_1(null, null);
                                                });
                                                break;
                                            }
                                        }
                                    }))
                                    {
                                        IsBackground = true
                                    };
                                    threadlist.Add(th);
                                    th.Start();

                                    #endregion separateList

                                    startTimer();
                                }
                                else
                                {
                                    return;
                                }
                            }
                        }
                    }
                }
                else
                {
                    listLists.Clear();
                    softwareMods.Add(new xssChecker(this, autoUpdateProxy) { UseAble = true });
                    softwareMods.Add(new sqlChecker(this, autoUpdateProxy) { UseAble = true });
                    softwareMods.Add(new sqlXssChecker(this, autoUpdateProxy) { UseAble = true });
                    if (string.IsNullOrEmpty(softwareMod))
                    {
                        addLog("Select a valid mod first to use software");
                        return;
                    }
                    else
                    {
                        var selectedMod = softwareMods.FirstOrDefault(func => func.Name.ToLower() == softwareMod);
                        if (selectedMod == null)
                        {
                            addLog("Selected mod doesent exists", "Error");
                            return;
                        }
                        else
                        {
                            if (selectedMod.UseAble == false)
                            {
                                addLog("Selected mod is not useable at this moment", "Error");
                                return;
                            }
                            else
                            {
                                working = true;
                                if (selectedMod.CanUse())
                                {
                                    if (selectedMod.NeedProxy)
                                    {
                                        loadProxyByUrl(false, proxyAutoUpdate);

                                        if (autoUpdateProxy)
                                        {
                                            loadProxyByUrl(true, proxyAutoUpdate);
                                        }
                                    }
                                    threadLimiter();

                                    #region separateList

                                    int diff = targetList.Count % CheckingThreads;
                                    int totalPerFile = (targetList.Count - diff) / CheckingThreads;
                                    int ineed = 0;
                                    List<string> test = new List<string>();
                                    int count = targetList.Count;
                                    int currentIndex = 0;
                                    while (true)
                                    {
                                        if (ineed + 1 == CheckingThreads)
                                        {
                                            ineed++;
                                            addLog($"All threads are activated now , we have {ineed} now");
                                            test = targetList.GetRange(currentIndex, targetList.Count - currentIndex);
                                            listLists.Add(new List<string>(test));
                                            test.Clear();
                                            break;
                                        }
                                        else
                                        {
                                            test = targetList.GetRange(currentIndex, totalPerFile);
                                            listLists.Add(new List<string>(test));
                                            test.Clear();
                                            ineed++;
                                            currentIndex += totalPerFile;
                                        }
                                    }

                                    if (debugMod)
                                    {
                                        addLog($"List : {targetList.Count}, Per list : {totalPerFile}, Ineed : {ineed}");
                                    }
                                    foreach (var item in listLists)
                                    {
                                        Thread th2 = new Thread(new ThreadStart(() =>
                                        {
                                            Starter(item, selectedMod, true, selectedMod.NeedProxy, selectedMod.CanUse, selectedMod.Config, selectedMod.NeedCaptcha, true);
                                        }))
                                        {
                                            IsBackground = true
                                        };
                                        threadlist.Add(th2);
                                        th2.Start();
                                    }
                                    Thread th = new Thread(new ThreadStart(() =>
                                    {
                                        while (true)
                                        {
                                            Thread.Sleep(10000);
                                            if (threadsActive <= 0 && selectedMod.transActions <= 0)
                                            {
                                                stop();
                                                break;
                                            }
                                        }
                                    }))
                                    {
                                        IsBackground = true
                                    };
                                    th.Start();
                                    threadlist.Add(th);
                                    startTimer();

                                    #endregion separateList
                                }
                                else
                                {
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public void stop()
        {
            try
            {
                working = false;
                threadsActive = 0;
                for (int i = 0; i < threadlist.Count; i++)
                {
                    threadlist[i].Abort();
                }
                threadlist.Clear();
                addLog("Stopped");
            }
            catch (Exception E)
            {
                HandleException(E);
                GC.Collect();
                Thread.Sleep(10000);
                stop();
            }
        }

        private void threadLimiter()
        {
            try
            {
                if (CheckingThreads > threadsLimit)
                {
                    addLog($"Your useable threads are limited , you can use max {threadsLimit}");
                    CheckingThreads = threadsLimit;
                }
            }
            catch (Exception E)
            {
                HandleException(E);
            }
        }

        public newHelper(Action<string, object> objLogger, bool needInvoke, MainWindow main)
        {
            mainFormObject = main;
            ownerCode = ownerName = ownerId = ownerMail = resultPath = softwareName = proxyType = proxyUrl = "";
            logger = objLogger;
            loggerInvoke = needInvoke;
            addLog("initialization successed");
        }
    }

    public interface modBase
    {
        string Name { get; set; }
        bool NeedProxy { get; set; }
        bool UseAble { get; set; }
        bool NeedCaptcha { get; set; }
        int transActions { get; set; }

        bool CanUse();

        bruteResult Config(ref string dork, string objectString, string proxy = null, string additionalOne = null, string additionalTwo = null);
    }

    public static class statistics
    {
        public static int Error = 0;
        public static int Proxies_FX = 0;
        public static int Proxies = 0;
        public static int TwoStep = 0;
        public static int Retries = 0;
        public static int dorksChecked = 0;
        public static int urlFound = 0;
        public static int unvulnerAble = 0;
        public static int bing = 0;
        public static int google = 0;
        public static int xss = 0;
        public static int sql = 0;
        public static int errors = 0;
    }

    public enum bruteResult
    {
        newUrl, error, retry, xss, sql, bing, google, itsSearcher, unvulnerAble, sqlXss
    }

    public class itsABug
    {
        public string id { get; set; }
        public string url { get; set; }
        public string vulnerability { get; set; }
        public string payload { get; set; }
        public string WAF { get; set; }
    }
}