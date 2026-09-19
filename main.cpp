/*
 * SandboxieIOC - sandboxed network/web IOC collection tool
 *
 * Runs a sample inside a Sandboxie box and records network activity
 * (sockets + DNS) exposed by Sandboxie's resource monitor. It then emits a
 * JSON report of network/web IOCs: URLs, DNS queries (domains), IP addresses
 * (from Sandboxie's explicit "IPv4:"/"IPv6:" trace fields), TCP/UDP
 * connections (ip:port), and authentication evidence (credentials embedded
 * in URLs).
 *
 * This driver program compiles Sandboxie's LGPL QSbieAPI into the executable
 * and, at runtime, drives the Sandboxie core (GPLv3). See README.md.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License (v3) as published by the
 * Free Software Foundation.
 */

#include <QCoreApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QTextStream>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QRegularExpression>
#include <QDateTime>
#include <QElapsedTimer>
#include <QSet>
#include <QStringList>
#include <QMap>
#include <QThread>
#include <algorithm>

#include "../QSbieAPI/SbieAPI.h"
#include "htmlreport.h"

// Monitor event types (Sandboxie driver api_flags.h, low byte of trace "Type").
enum {
    M_SYSCALL  = 0x01, M_PIPE = 0x02,  M_IPC    = 0x03, M_WINCLASS = 0x04,
    M_DRIVE    = 0x05, M_COMCLASS = 0x06, M_RTCLASS = 0x07, M_IGNORE = 0x08,
    M_IMAGE    = 0x09, M_FILE  = 0x0A,  M_KEY     = 0x0B, M_OTHER  = 0x0C,
    M_NETFW    = 0x0D, M_SCM   = 0x0E,  M_APICALL = 0x0F, M_RPC    = 0x10,
    M_DNS      = 0x11, M_HOOK  = 0x12
};

static QTextStream gOut(stdout);
static QTextStream gErr(stderr);

// ---------------------------------------------------------------------------
// Network / web parsing helpers
//
// Sandboxie logs network activity at the socket/DNS level:
//   NetFw (0x0D): "Network Traffic; Port: <p>; Prot: <proto>; IPv4: x.x.x.x"
//                 (or "; IPv6: ...")
//   DNS   (0x11): "DNS Request Begin: <host> ..."
//                 "DNS Request Found: <host> ...; IPv4: x.x.x.x"
// It does NOT expose HTTP headers/payloads, so "authentication" is limited to
// credentials embedded in URLs and auth-like tokens visible in names/strings.
// ---------------------------------------------------------------------------

static bool isValidIpv4(const QString& s)
{
    const QStringList parts = s.split('.');
    if (parts.size() != 4)
        return false;
    foreach (const QString& p, parts) {
        bool ok = false;
        const int n = p.toInt(&ok);
        if (!ok || n < 0 || n > 255)
            return false;
    }
    return true;
}

// Real IPs are only those in Sandboxie's explicit "IPv4:" / "IPv6:" fields.
static QSet<QString> extractIpv4(const QString& text)
{
    QSet<QString> out;
    static QRegularExpression re(
        "IPv4:\\s*([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})");
    auto it = re.globalMatch(text);
    while (it.hasNext()) {
        const QString g = it.next().captured(1);
        if (isValidIpv4(g))
            out.insert(g);
    }
    return out;
}

static QSet<QString> extractIpv6(const QString& text)
{
    QSet<QString> out;
    static QRegularExpression re("IPv6:\\s*([0-9a-fA-F:]+)");
    auto it = re.globalMatch(text);
    while (it.hasNext())
        out.insert(it.next().captured(1));
    return out;
}

static QSet<QString> extractUrls(const QString& text)
{
    QSet<QString> out;
    static QRegularExpression re("https?://[^\\s\"'<>)]+",
                                 QRegularExpression::CaseInsensitiveOption);
    auto it = re.globalMatch(text);
    while (it.hasNext())
        out.insert(it.next().captured(0));
    return out;
}

// Credentials embedded in a URL, e.g. http://user:pass@host/
static QSet<QString> extractUrlCredentials(const QString& text)
{
    QSet<QString> out;
    static QRegularExpression re("https?://([^/\\s@]+)@",
                                 QRegularExpression::CaseInsensitiveOption);
    auto it = re.globalMatch(text);
    while (it.hasNext()) {
        const QString creds = it.next().captured(1);
        if (creds.contains(':'))
            out.insert(creds);
    }
    return out;
}

static void addUnique(QJsonArray& arr, const QString& v)
{
    if (v.isEmpty())
        return;
    // cheap linear dedup (arrays here stay small)
    for (const QJsonValue& x : arr)
        if (x.toString() == v)
            return;
    arr.append(v);
}

static void addUniqueObject(QJsonArray& arr, const QJsonObject& o, const QString& key)
{
    const QString k = o[key].toString();
    for (const QJsonValue& x : arr)
        if (x.toObject()[key].toString() == k)
            return;
    arr.append(o);
}

// Configure a dedicated analysis box for verbose introspection.
static void configureBox(CSandBox* box, bool blockNetwork, bool dropAdmin)
{
    // Verbose access traces (mirrors OptionsAdvanced UI values).
    box->SetText("CallTrace", "*");
    box->SetText("FileTrace", "*");
    box->SetText("PipeTrace", "*");
    box->SetText("KeyTrace", "*");
    box->SetText("IpcTrace", "*");
    box->SetText("GuiTrace", "*");
    box->SetText("ClsidTrace", "*");
    box->SetText("NetFwTrace", "*");
    box->SetBool("DnsTrace", true);
    box->SetBool("ApiTrace", true);
    box->SetBool("HookTrace", true);
    box->SetBool("DebugTrace", true);
    box->SetBool("ErrorTrace", true);

    if (blockNetwork) {
        box->SetBool("BlockNetworkFiles", true);
        // Classic device-based internet block (deny InternetAccessDevices).
        box->AppendText("ClosedFilePath", "!<InternetAccess>,InternetAccessDevices");
    }
    if (dropAdmin)
        box->SetBool("DropAdminRights", true);
}

// Terminate any live processes then clean the box (async -> poll to completion).
static void resetBox(CSandBox* box)
{
    box->TerminateAll();
    QThread::msleep(300);
    box->Api()->UpdateProcesses(0, false);
    SB_PROGRESS pr = box->CleanBox();
    if (pr.IsError())
        return;
    CSbieProgressPtr p = pr.GetValue();
    while (p && !p->IsFinished())
        QThread::msleep(50);
}

static void writeReport(const QJsonObject& report, const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        gErr << "error: cannot write report to " << path << "\n";
        return;
    }
    f.write(QJsonDocument(report).toJson(QJsonDocument::Indented));
    f.close();
    gOut << "[*] report written to " << QDir::toNativeSeparators(path) << "\n";
}

static void printSummary(const QJsonObject& report)
{
    gOut << "\n============================================================\n";
    gOut << "  SandboxieIOC - Network / web analysis summary\n";
    gOut << "============================================================\n";

    const QJsonObject ioc = report["iocs"].toObject();
    const QJsonArray urls  = ioc["urls"].toArray();
    const QJsonArray ips   = ioc["ips"].toArray();
    const QJsonArray dns   = ioc["domains"].toArray();
    const QJsonArray conns = ioc["connections"].toArray();
    const QJsonArray auth  = ioc["authentication"].toArray();

    gOut << "URLs                 : " << urls.size() << "\n";
    gOut << "IP addresses         : " << ips.size() << "\n";
    gOut << "DNS queries          : " << dns.size() << "\n";
    gOut << "Connections (ip:port): " << conns.size() << "\n";
    gOut << "Authentication found : " << auth.size() << "\n";

    if (urls.size()) {
        gOut << "\n-- URLs --\n";
        for (const QJsonValue& v : urls)
            gOut << "  " << v.toObject()["url"].toString() << "\n";
    }
    if (ips.size()) {
        gOut << "\n-- IP addresses --\n";
        for (const QJsonValue& v : ips)
            gOut << "  " << v.toObject()["ip"].toString() << "\n";
    }
    if (dns.size()) {
        gOut << "\n-- DNS queries --\n";
        for (const QJsonValue& v : dns) {
            const QJsonObject o = v.toObject();
            gOut << "  " << o["name"].toString();
            const QString pid = o["pid"].toString();
            if (!pid.isEmpty())
                gOut << QString(" (pid %1)").arg(pid);
            gOut << "\n";
        }
    }
    if (conns.size()) {
        gOut << "\n-- Connections (ip:port) --\n";
        for (const QJsonValue& v : conns) {
            const QJsonObject o = v.toObject();
            gOut << "  " << o["endpoint"].toString()
                 << "  proto=" << o["protocol"].toString() << "\n";
        }
    }
    if (auth.size()) {
        gOut << "\n-- Authentication --\n";
        for (const QJsonValue& v : auth) {
            const QJsonObject o = v.toObject();
            gOut << "  [" << o["kind"].toString() << "] "
                 << o["evidence"].toString() << "\n";
        }
    }
    gOut << "\n============================================================\n";
}

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("SandboxieIOC");
    QCoreApplication::setApplicationVersion("1.0");

    QCommandLineParser parser;
    parser.setApplicationDescription(
        "Sandboxed executable analysis & IOC collection tool");
    parser.addHelpOption();
    parser.addVersionOption();

    parser.addPositionalArgument("sample",
        "Executable to analyze (path or command line)");

    QCommandLineOption boxOpt(
        {"b", "box"}, "Sandbox to use (default: IOCAnalysis)", "name", "IOCAnalysis");
    parser.addOption(boxOpt);
    QCommandLineOption outOpt(
        {"o", "output"}, "JSON report path (default: ioc_report.json)", "file",
        "ioc_report.json");
    parser.addOption(outOpt);
    QCommandLineOption timeoutOpt(
        "timeout", "Analysis timeout in seconds (default: 60)", "sec", "60");
    parser.addOption(timeoutOpt);
    QCommandLineOption netOpt(
        "block-network", "Block internet/network access in the box");
    parser.addOption(netOpt);
    QCommandLineOption adminOpt(
        "drop-admin", "Enable DropAdminRights in the box");
    parser.addOption(adminOpt);
    QCommandLineOption keepOpt(
        "keep-box", "Do not clean (delete) the sandbox after analysis");
    parser.addOption(keepOpt);

    parser.process(app);

    const QStringList args = parser.positionalArguments();
    if (args.isEmpty()) {
        gErr << "error: no sample specified (see --help)\n";
        return 2;
    }
    const QString sample = args.join(" ");
    const int timeoutSec = parser.value(timeoutOpt).toInt();
    const QString reportPath = parser.value(outOpt);

    // ---- Connect ----
    CSbieAPI api;
    // Connect as a regular client (takeOver=false): becoming the session
    // leader requires a Sandboxie-signed process (SandMan/SbieCtrl), which
    // this unsigned tool is not. Client operations (enum/monitor/run) work
    // without the leader role; SandMan remains the leader.
    SB_STATUS status = api.Connect(false, true);
    if (status.IsError()) {
        gErr << "error: failed to connect to Sandboxie driver"
             << " (status 0x" << QString::number((quint32)status.GetStatus(), 16)
             << "). Is Sandboxie installed and the SbieDrv driver loaded?\n";
        return 1;
    }
    gOut << "[*] connected to Sandboxie\n";

    api.ReloadBoxes(true);
    const QString boxName = parser.value(boxOpt);

    // ---- Prepare box ----
    CSandBoxPtr box = api.GetBoxByName(boxName);
    if (!box) {
        gOut << "[*] creating sandbox '" << boxName << "'\n";
        status = api.CreateBox(boxName, true);
        if (status.IsError()) {
            gErr << "error: failed to create sandbox '" << boxName << "'\n";
            return 1;
        }
        box = api.GetBoxByName(boxName);
    }
    if (!box) {
        gErr << "error: sandbox not found\n";
        return 1;
    }

    resetBox(box.data());
    configureBox(box.data(), parser.isSet(netOpt), parser.isSet(adminOpt));
    gOut << "[*] box '" << boxName << "' configured\n";

    const QString fileRoot = box->GetFileRoot();
    gOut << "[*] box file root: " << QDir::toNativeSeparators(fileRoot) << "\n";

    // ---- Enable monitor ----
    api.ClearTrace();
    status = api.EnableMonitor(true);
    if (status.IsError())
        gErr << "warning: could not enable resource monitor\n";

    gOut << "[*] launching sample...\n";
    QElapsedTimer timer;
    timer.start();

    SB_RESULT(quint32) startRc = api.RunStart(boxName, sample);
    if (startRc.IsError()) {
        gErr << "error: failed to launch sample (status 0x"
             << QString::number((quint32)startRc.GetStatus(), 16) << ")\n";
        api.EnableMonitor(false);
        return 1;
    }

    // ---- Watch loop ----
    bool terminated = false;
    while (timer.elapsed() / 1000 < timeoutSec) {
        api.UpdateProcesses(0, false);
        if (box->GetActiveProcessCount() == 0) {
            QThread::msleep(1500);          // catch late descendants
            api.UpdateProcesses(0, false);
            if (box->GetActiveProcessCount() == 0)
                break;
        }
        QThread::msleep(800);
    }

    if (box->GetActiveProcessCount() > 0) {
        gOut << "[*] timeout reached - terminating processes\n";
        box->TerminateAll();
        terminated = true;
    }
    QThread::msleep(500);
    api.UpdateProcesses(0, false);

    // ---- Pull process tree info ----
    QJsonArray procArr;
    const QMap<quint32, CBoxedProcessPtr> procs = api.GetAllProcesses();
    QList<quint32> pids = procs.keys();
    std::sort(pids.begin(), pids.end());

    foreach (quint32 pid, pids) {
        CBoxedProcessPtr p = procs[pid];
        if (!p || p->GetBoxName().compare(boxName, Qt::CaseInsensitive) != 0)
            continue;
        QJsonObject o;
        o["pid"] = (int)pid;
        o["ppid"] = (int)p->GetParendPID();
        o["name"] = p->GetProcessName();
        o["path"] = p->GetFileName();
        o["cmdline"] = p->GetCommandLine();
        procArr.append(o);
    }

    // ---- Parse traces for NETWORK / WEB only ----
    QJsonArray dnsArr;
    QSet<QString> dnsSet;
    QJsonArray connArr;
    QSet<QString> connSet;
    QJsonArray urlArr;
    QSet<QString> urlSet;
    QJsonArray ipArr;
    QSet<QString> ipSet;
    QJsonArray authArr;
    QSet<QString> authSet;

    auto collectUrl = [&](const QString& text) {
        const QSet<QString> urls = extractUrls(text);
        foreach (const QString& u, urls) {
            if (!urlSet.contains(u)) {
                urlSet.insert(u);
                QJsonObject o;
                o["url"] = u;
                urlArr.append(o);
            }
            // credentials embedded in URL -> authentication evidence
            const QSet<QString> creds = extractUrlCredentials(u);
            foreach (const QString& c, creds) {
                if (!authSet.contains(c)) {
                    authSet.insert(c);
                    QJsonObject a;
                    a["kind"] = "url_credentials";
                    a["evidence"] = c;
                    authArr.append(a);
                }
            }
        }
    };

    const QVector<CTraceEntryPtr>& trace = api.GetTrace();
    foreach (const CTraceEntryPtr& e, trace) {
        if (!e)
            continue;
        const quint32 type = (quint32)e->GetType();
        QString msg = e->GetMessage().trimmed();
        if (msg.isEmpty())
            msg = e->GetName().trimmed();
        const quint32 pid = e->GetProcessId();

        switch (type) {
        case M_DNS: {
            // Only these DNS messages carry a real queried name.
            // "DNS Request End (Hdl: ...)" / "DNS Filtered Request End (...)"
            // have no name and are discarded.
            static QRegularExpression namePrefix(
                "^(DNS Request Begin|DNS Request Found|DNS Filtered Response):\\s*",
                QRegularExpression::CaseInsensitiveOption);
            QRegularExpressionMatch pm = namePrefix.match(msg);
            if (!pm.hasMatch())
                break;

            QString host = msg.mid(pm.capturedLength()).trimmed();
            // cut at the first '(' , ',' or ';' field boundary
            int best = host.length();
            bool cut = false;
            for (const QChar sep : { QChar('('), QChar(','), QChar(';') }) {
                int p = host.indexOf(sep);
                if (p != -1 && p < best) { best = p; cut = true; }
            }
            if (cut)
                host = host.left(best).trimmed();

            // A real hostname contains at least one letter.
            static QRegularExpression looksLikeName("[A-Za-z]");
            bool valid = !host.isEmpty() && looksLikeName.match(host).hasMatch();

            if (valid && !dnsSet.contains(host)) {
                dnsSet.insert(host);
                QJsonObject d;
                d["name"] = host;
                d["pid"] = (int)pid;
                dnsArr.append(d);
                collectUrl(msg);
            }
            break;
        }
        case M_NETFW: {
            // "Network Traffic; Port: <p>; Prot: <proto>[; IPv4: x.x.x.x][; IPv6: ...]"
            // Most network IOCs here are IP-based (the connection's remote IP
            // is only available in the WFP/kernel path; the hook captures
            // the local socket peer via the 'IPv4:'/'IPv6:' field appended by
            // WSA_DumpIP).
            QString port, protocol;
            QRegularExpression portRe("Port:\\s*(\\d+)");
            QRegularExpressionMatch pm = portRe.match(msg);
            if (pm.hasMatch())
                port = pm.captured(1);
            QRegularExpression protoRe("Prot:\\s*(\\d+)");
            QRegularExpressionMatch gm = protoRe.match(msg);
            if (gm.hasMatch())
                protocol = gm.captured(1);

            const QSet<QString> ip4 = extractIpv4(msg);
            const QSet<QString> ip6 = extractIpv6(msg);

            auto addConn = [&](const QString& ip) {
                const QString ep = port.isEmpty() ? ip : ip + ":" + port;
                if (connSet.contains(ep))
                    return;
                connSet.insert(ep);
                QJsonObject o;
                o["endpoint"] = ep;
                o["ip"] = ip;
                o["port"] = port;
                o["protocol"] = protocol;
                o["pid"] = (int)pid;
                connArr.append(o);
            };
            foreach (const QString& ip, ip4) addConn(ip);
            foreach (const QString& ip, ip6) addConn(ip);

            foreach (const QString& ip, ip4)
                if (!ipSet.contains(ip)) { ipSet.insert(ip); QJsonObject o; o["ip"] = ip; ipArr.append(o); }
            foreach (const QString& ip, ip6)
                if (!ipSet.contains(ip)) { ipSet.insert(ip); QJsonObject o; o["ip"] = ip; ipArr.append(o); }

            collectUrl(msg);
            break;
        }
        default:
            // Also scan arbitrary messages (debug, api, etc.) for URLs and
            // auth tokens; ignore IPs here to avoid false positives.
            collectUrl(msg);
            break;
        }
    }

    // ---- Build network-only report ----
    QJsonObject meta;
    meta["tool"] = "SandboxieIOC";
    meta["version"] = "1.0";
    meta["date"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    meta["sample"] = sample;
    meta["box"] = boxName;
    meta["sandboxie_version"] = api.GetVersion();
    meta["timeout_seconds"] = timeoutSec;
    meta["terminated_by_timeout"] = terminated;

    QJsonObject ioc;
    ioc["urls"] = urlArr;
    ioc["ips"] = ipArr;
    ioc["domains"] = dnsArr;
    ioc["connections"] = connArr;
    ioc["authentication"] = authArr;

    QJsonObject report;
    report["metadata"] = meta;
    report["processes"] = procArr;
    report["iocs"] = ioc;

    writeReport(report, reportPath);
    printSummary(report);

    // Also emit a self-contained HTML dashboard next to the JSON.
    {
        QString htmlPath = reportPath;
        if (htmlPath.endsWith(".json", Qt::CaseInsensitive))
            htmlPath.chop(5);
        htmlPath += ".html";
        QFile hf(htmlPath);
        if (hf.open(QIODevice::WriteOnly | QIODevice::Text)) {
            hf.write(renderNetworkReportHtml(report).toUtf8());
            hf.close();
            gOut << "[*] HTML dashboard written to "
                 << QDir::toNativeSeparators(htmlPath) << "\n";
        }
    }

    // ---- Teardown ----
    api.EnableMonitor(false);
    if (!parser.isSet(keepOpt)) {
        gOut << "[*] cleaning sandbox\n";
        resetBox(box.data());
    }
    api.Disconnect();
    return 0;
}




