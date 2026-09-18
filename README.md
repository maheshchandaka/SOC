Start-Process ms-settings:
=ISNUMBER(MATCH(A2, B2:B3328, 0))


IP is clean
IP tagged as VPN
Observed malicious signin activity from IP successfully accessing OfficeHome resource.
User compromised through AiTM phishing.
Observed successful/failed user signin activity from IP accessing FIXME with an unmanaged Windows10/ MacOS device having useragent: 
No successful sign-in activity was found from the IP. All attempts from the IP were failed but 'Correct Password' was used in primary authentication.    
No successful signin activity found from IP
Observed office activity from IP for MailItemsAccessed operations.
No office or azure activity found from IP
User's most usual signin activity is observed from IP: FIXME, Location: FIXME with managed Windows device: 
Observed successful signin activity from same useragent in the past
No suspicious url clicks found for user.
No other security alerts found for user
No new MFA method addition detected for account 
Looks like user activity from personal Android Apple MacOS mobile device
User activity from personal Android/Apple mobile device. Closing as BP.
Observed successful user signin activity from same IP with managed device: 
Observed successful signin activity from same IP by multiple users with managed devices.
Known IP in customer environment. Activity from AD managed device. Closing as BP.
Could you please check with user: FIXME about the VPN usage and if the signin activity is expected from IP: FIXME? If not, please reset user credentials and revoke all active sessions.
Could you please check with user: FIXME and validate if the signin activity is expected from IP: FIXME? If not, please reset user credentials and revoke all active sessions.


User: 
Host: 
User clicked a phishing url.
Url clicked: 
The url contains a document link and redirects to fake Microsoft credential harvester page.
Effective Url:
Email Details:
Observed multiple mails from same sender
From all recipients, only user: FIXME clicked the phishing link. But there are no network and proxy connections to the final phishing domain: FIXME
Verified user signin activity- Nothing malicious found; all signins are from AD joined device: FIXME only
Observed successful device network events to phishing domain
Blocked phishing domain in Defender
Checked user signin activity- Nothing suspicious found
No new MFA method addition detected for account 
Required Actions by customer
- The user has been marked as compromised. If a Conditional Access policy is configured, their password will be reset automatically and this request can be ignored. If no such policy is in place, please reset their credentials manually.
- Please check with user: FIXME about the activity and whether any credentials were entered after clicking the URL. If so, please reset the user's credentials.
- Please block the domain FIXME or provide your approval.
- Please block the sender and purge all mails.
- If the sender: FIXME is known, temporarily block it and report the compromise through the appropriate escalation channels. Maintain the restriction until the account has been remediated and confirmed secure.


Nothing malicious found in the payload. Signature pattern mismatch. Traffic is internal. Closing as FP.



- Confiscate and format the USB drive
- Advise the user: FIXME not to connect unauthorized/malicious external drives to FIXME devices
Suspected identity theft (pass-the-ticket) 


DeviceNetworkEvents
| where DeviceName contains "FIXME"
| where LocalIP contains "FIXME"
| summarize min(TimeGenerated), max(TimeGenerated) by DeviceName, LocalIP
| sort by max_TimeGenerated desc

**ClickFIX**

- The user has been marked as compromised. If a Conditional Access policy is configured, their password will be reset automatically and this request can be ignored. If no such policy is in place, please reset their credentials manually.
- Please remove the registry key from the device before removing from isolation, or re-image the device if the registry key cannot be removed completely.
- Disable or restrict Windows Run (Win+R) and Windows power menu (Win+X) via Group Policy/AppLocker/WDAC to prevent users from launching PowerShell, Command Prompt, and Windows Terminal commonly abused in ClickFix attacks.
- Conduct user awareness training on ClickFix attacks, emphasizing that users should never copy, paste, or execute commands from websites, CAPTCHAs, browser pop-ups, emails, or unsolicited support messages.
Mail Bombing and IT impersonation



Security Alerts:
- Mail bombing activity detected
- Suspicious Volume of Received Emails
- IT Support Teams Voice phishing following mail bombing activity
- Microsoft Teams chat initiated by a suspicious external user 
- Potentially malicious IT support Teams impersonation post mail bombing
- Suspicious activity using Quick Assist

The primary alert "IT Support Teams Voice phishing following mail bombing activity" was generated on 2026-08-25 20:09:50+00:00, describing mass newsletter subscriptions used to overwhelm mailboxes and subsequent voice calls aiming at remote-access tools or malware that could lead to ransomware.


The user mailbox received FIXME spam subscription confirmation and newsletter emails from different senders between FIXME and FIXME.
 
At FIXME , an external account contacted the user through MS Teams.
DisplayName: 
External account: 
 
It is a social engineering technique in which an attacker impersonates IT team after sending bulk spam emails, then contacts the user and convinces them to join a Microsoft Teams call in order to remotely execute malicious commands and deploy payloads on the user’s machine.
 
A MicrosoftTeams ChatCreated and MessageSent events was present, matching the alert’s concern about Teams impersonation, but a detailed review found no Quick Assist, remote assistance, or screen-share events found on user host:

No suspicious url clicks found for user.
 
Checked user signin activity- nothing malicious found
 
No new MFA methods, or new device registrations were found for Account.

No signs of account or host compromise were identified. It appears the user may not have attended the malicious call or shared their screen.

Recommendations
- Please check with the user FIXME to confirm whether they attended the suspicious Microsoft Teams call and shared their system screen. If yes, please isolate their device.
- Please add the external sender: FIXME to blocklist in Microsoft Teams admin center.
Ref: https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings#block-external-users
- Please validate with the user for any signs of social engineering attempts, as mail bombing can be used to distract users from secondary attacks. Give a heads-up about incoming external Teams calls impersonating IT support.  
- If mailbox disruption persists, consider enabling stricter spam filtering or creating rules to automatically move bulk subscription emails to junk or quarantine folders.  
- Please purge all spam mails from the user mailbox.
- Please disable Quick Assist via Group Policy and explicitly allowlist only the external Teams tenants you want to be able to interact with your users.  
- Please enforce a MS Teams policy to restrict anonymous users from joining or starting Teams calls without verification.  
- Please raise awareness among users about these social engineering techniques including impersonation, fake IT support calls, and malicious meeting invitations.


OfficeActivity
| where Operation has_any ("CallParticipantDetail", "ChatCreated","MessageSent")
| search "FIXME" //affected user

DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "QuickAssist.exe"
    or ProcessCommandLine has "ms-quick-assist:"


EmailEvents
| where EmailDirection == "Inbound"
| where Subject has_any (
   "account has been created",
    "subscription",
    "verification code",
    "verification key",
    "verify your email",
    "subscribe",
    "marketing",
    "verify",
    "newsletter",
    "confirm",
    "welcome",
    "activate account",
    "sign up",
    "email confirmation",
    "one-time password",
    "otp"
)
| where RecipientEmailAddress contains "FIXME"



    let RMMTools = dynamic([
    "teamviewer.exe",
    "teamviewer_service.exe",
    "anydesk.exe",
    "anydeskmsi.exe",
    "screenconnect.clientservice.exe",
    "connectwisecontrol.client.exe",
    "logmein.exe",
    "logmeinrescue.exe",
    "gotoassist.exe",
    "splashtop.exe",
    "srmanager.exe",
    "ateraagent.exe",
    "ateraagent",
    "agentmon.exe",
    "ninjarmmagent.exe",
    "ninjaone.exe",
    "kaseyaagent.exe",
    "agent.exe",
    "ltservice.exe",
    "labtech.exe",
    "bomgar-scc.exe",
    "bomgar-rdp.exe",
    "rustdesk.exe",
    "dwagent.exe",
    "meshagent.exe",
    "takecontrol.exe",
    "vncserver.exe",
    "winvnc.exe",
    "tvnserver.exe",
    "remoteutilities.exe", "QuickAssist.exe"
]);
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where DeviceName contains "FIXME"
| extend ProcName = tolower(FileName)
| where ProcName in (RMMTools)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA1
| order by Timestamp desc





let Attacker= "FIXME";
OfficeActivity
| where Operation has_any ("CallParticipantDetail", "ChatCreated")
| extend AffectedUser= tolower(Attendees[0].UPN)
| where UserId has Attacker or Attendees[0].DisplayName has Attacker //or AffectedUser has Attacker
| extend TempValue = Attendees[0].DisplayName 
| extend  AffectedUser  = iff(not(UserId contains "onmicrosoft.com"), UserId, AffectedUser),  UserId = iff(not(UserId contains "onmicrosoft.com"), TempValue, UserId)
| where AffectedUser !has Attacker
| extend ItemName = iff(ItemName contains "unq.gbl.spaces", "", ItemName)
| extend  MessageSender= Members[0].UPN 
| extend  MessageReceiver= Members[1].UPN 
| project TimeGenerated, MessageSender, MessageReceiver, CommunicationType, UserId,Operation,AffectedUser, ItemName, JoinTime, LeaveTime


let SpamEmails =
EmailEvents
| where TimeGenerated > ago(1d)
| where EmailDirection == "Inbound"
| where Subject has_any (
    "account has been created",
    "subscription",
    "verification code",
    "verification key",
    "verify your email",
    "subscribe",
    "marketing",
    "verify",
    "newsletter",
    "confirm",
    "welcome",
    "activate account",
    "sign up",
    "email confirmation",
    "one-time password",
    "otp"
);
let TargetUsers =
SpamEmails
| summarize TotalSpamEmails=count() by RecipientEmailAddress
| where TotalSpamEmails >= 300;
let PeakHour =
SpamEmails
| join kind=inner TargetUsers on RecipientEmailAddress
| summarize HourlyCount=count() by RecipientEmailAddress, HourBin=bin(TimeGenerated, 1h)
| summarize arg_max(HourlyCount, HourBin) by RecipientEmailAddress;
SpamEmails
| join kind=inner TargetUsers on RecipientEmailAddress
| summarize
    FirstEmail=min(TimeGenerated),
    LastEmail=max(TimeGenerated),
    TotalSpamEmails=count()
    by RecipientEmailAddress
| join kind=leftouter PeakHour on RecipientEmailAddress
| project
    RecipientEmailAddress,
    FirstEmail,
    LastEmail,
    TotalSpamEmails,
    PeakHourWindow=strcat(format_datetime(HourBin,'yyyy-MM-dd HH:mm'),
                          " - ",
                          format_datetime(HourBin + 1h,'HH:mm')),
    PeakHourEmailCount=HourlyCount
| order by TotalSpamEmails desc
| project RecipientEmailAddress, TotalSpamEmails



_GetWatchlist('DomainControllersWatchlist')
| where DeviceName contains "FIXME" // Device Name

**To hunt for Ransom Note**

DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName matches regex @"(?i).*\.(txt|html|htm|hta|bmp|png|gif|jpg|jpeg)$"
| where FileName matches regex @"(?i)(decrypt|howdecrypt|readme|recover|restore|ransom|instruction|help|payment|files)"
| where not(FolderPath has_any (
    "\\windows\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programdata\\"
))
| project
    Timestamp,
    DeviceName,
    FolderPath,
    FileName,
    ActionType,
    FileSize,
    SHA1,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc

****To find accessed emails for compromised account
****

OfficeActivity
| where TimeGenerated > ago(30d)
| where  Client_IPAddress has_any ("FIXME")
| where UserId == "FIXME"
| extend ParsedFolders = parse_json(Folders)
| mv-expand ParsedFolders
| extend FolderPath = tostring(ParsedFolders.Path)
| extend FolderItems = parse_json(tostring(ParsedFolders.FolderItems))
| mv-expand FolderItems
| extend EmailSubject = tostring(FolderItems.Subject)
| project TimeGenerated, UserId, Client_IPAddress, FolderPath, EmailSubject
| project-reorder TimeGenerated, Client_IPAddress, UserId, FolderPath, EmailSubject
| where isnotempty(FolderPath)
| where isnotempty(EmailSubject)
| sort by TimeGenerated asc
Phishing Url Analysis



let url = "FIXME"; //url domain
search in (EmailUrlInfo,UrlClickEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceEvents,BehaviorEntities)
Timestamp between (ago(3d) .. now())
and (RemoteUrl has url
or FileOriginUrl has url
or FileOriginReferrerUrl has url
or Url has url
)
| take 100


EmailEvents
| where SenderFromAddress contains "FIXME" // sender address
| project NetworkMessageId
| join kind = inner (
UrlClickEvents
|project Timestamp,NetworkMessageId, AccountUpn,ActionType,Url
) on NetworkMessageId


EmailUrlInfo
| where Url contains "FIXME"       //Original Url domain
| project NetworkMessageId
| join kind = inner (
EmailEvents
|project Timestamp,NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject
) on NetworkMessageId
Proxy Logs



CommonSecurityLog 
| where DeviceVendor contains "Zscaler" 
| where RequestURL contains "FIXME"          // Repalce with Domain
Ldap Query



IdentityQueryEvents
| where DeviceName contains "sevadfsh02v" and Protocol == "Ldap" and DestinationDeviceName contains "sevad01v"
CallReported



CloudAppEvents
| where TimeGenerated >= ago(1d)
| where AccountDisplayName contains "Smith"
| where Application == "Microsoft Teams"
| where ActionType == "CallReported"
| extend ParsedData = parse_json(RawEventData)
| extend 
    SubmissionId = tostring(ParsedData.SubmissionId),
    CallId = tostring(ParsedData.ReportMetadata.CallId),
    OtherReportedEntities = ParsedData.ReportMetadata.OtherReportedEntities
| project TimeGenerated, AccountDisplayName, Application, ActionType, SubmissionId, CallId, OtherReportedEntities, IPAddress, RawEventData
| order by TimeGenerated desc
| extend json = parse_json(OtherReportedEntities)
| mv-expand json
| extend DisplayName = tostring(json.DisplayName),
         MRI = tostring(json.MRI)
| extend Phone = extract(@"(\+\d+)", 1, MRI)
| extend Result = strcat("DisplayName: ", DisplayName, " (", Phone, ")")
| project Result
Based on the pattern, it appears the user is actively reporting spam calls from multiple external numbers.
If the user continues to receive multiple calls from various numbers, we recommend implementing the following controls:
1. Disable External Calls or Restrict PSTN Calling for the user
2. Configure Caller ID and Spam Filtering (for Teams Phone):
  - Enable Block Anonymous Calls
  - Adjust Inbound Call Restrictions
Please let us know if any additional actions or assistance are required.
Proxy Logs



custProxyEvents
//| where url_filter_action_s != "allow" and url_filter_action_s != "whitelist"
//| where url_filter_action_s == "deny"
| where url_s contains "FIXME" // add url or domain in FIXME
//| where client_ip_s == "FIXME" // add IP of device ( add this line if u know IP)
Firewall logs



custFirewallEvents
| where ip_src_s == "FIXME" // source ip
| where ip_dst_s == "FIXME" // destination ip
| where action_s == "ACCEPT" // ACCEPT, DROP, REJECT
 

For Signin logs



let IPs = dynamic(["188.130.221.181", "45.11.20.150"]);
custSigninLogs
| where IPAddress has_any (IPs)

Both Failed and Successful logs



custSigninLogs
//| where UserDisplayName contains "John Doe" // find name of the user in Defender or custOnPremADUserList
| where UserPrincipalName contains "FIXME_EMAIL" // find email of the user in Defender or custOnPremADUserList
| where IPAddress == "FIXME_IP"
//| distinct IPAddress //unique ip adresses
//| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName, ClientAppUsed, DeviceDetail, IPAddress
//| summarize count() by UserPrincipalName, AppDisplayName, ResourceDisplayName, ClientAppUsed, IPAddress
Only Successful logs



custSigninLogs
| extend FirstFAStatus = tostring(parse_json(AuthenticationDetails)[0]["succeeded"])
| extend FirstFAAuthMethod = tostring(parse_json(AuthenticationDetails)[0]["authenticationMethod"])
| where (FirstFAStatus=~ "True" and FirstFAAuthMethod == "Password") or ResultType == "0"
| where UserPrincipalName contains "FIXME1" and IPAddress contains "FIXME2"//Replace FIXME1 with value of AccountCustomEntity and FIXME2 with IPCustomEntity
//| distinct IPAddress //unique ip adresses
//| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName, ClientAppUsed, DeviceDetail, IPAddress
//| summarize count() by UserPrincipalName, AppDisplayName, ResourceDisplayName, ClientAppUsed, IPAddress
 


let connect =(
DeviceNetworkEvents
| where DeviceName contains "des335wks7001"
| project RemoteUrl
);
UrlClickEvents
| where Url in (connect)
|project Timestamp,NetworkMessageId, AccountUpn,ActionType,Url
