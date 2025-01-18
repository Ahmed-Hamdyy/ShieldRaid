# Security Events Classification

## High Severity Events

### Authentication & Account Management
- **4625**: Failed login attempts
- **4648**: Explicit credential logon
- **4720**: User account creation
- **4723**: Password change attempt
- **4726**: User account deletion
- **4728**: Member added to privileged group
- **4732**: Member added to local security group
- **4756**: Member added to universal security group
- **4765**: SID History added to account
- **4766**: Attempt to add SID History to account
- **4794**: Directory Services restore mode admin password set

### System Security
- **4616**: System time was changed
- **4657**: Registry value modified
- **4697**: Service installation
- **4698**: Scheduled task creation
- **4699**: Scheduled task deletion
- **4719**: System audit policy changed
- **4946**: Rule added to Windows Firewall exception list
- **5124**: Security policy in Group Policy was changed
- **6281**: Code integrity determined that the page hashes of an image file are not valid

### Network Security
- **4825**: RDP access denied due to client's security configuration
- **4946**: Rule added to Windows Firewall
- **4947**: Rule modified in Windows Firewall
- **4950**: Windows Firewall settings changed
- **5156**: Windows Filtering Platform blocked a connection
- **5157**: Windows Filtering Platform blocked a connection

### Setup & Configuration
- **11708**: Critical setup configuration changes
- **11724**: Application installation with elevated privileges

## Medium Severity Events

### Authentication & Account Management
- **4624**: Successful account login
- **4634**: Account logoff
- **4647**: User initiated logoff
- **4649**: A replay attack was detected
- **4660**: Object deletion events
- **4663**: Object access attempt
- **4670**: Permissions on an object were changed
- **4738**: User account change
- **4767**: User account unlocked

### System Operations
- **1102**: Audit log cleared
- **4688**: New process created
- **4689**: Process exited
- **4690**: Handle to an object was duplicated
- **4692**: Backup of data protection master key was attempted
- **4693**: Recovery of data protection master key was attempted
- **7036**: Service start/stop events
- **7045**: New service installed

### Setup & Configuration
- **11707**: Setup configuration modifications
- **11714**: Application removal
- **11806**: Installation progress status

### Network Activity
- **4985**: State of a transaction changed
- **5058**: Key file operation
- **5140**: Network share was accessed
- **5145**: Network share check
- **5154**: Windows Filtering Platform permitted an application or service to listen on a port
- **5155**: Windows Filtering Platform blocked an application or service from listening on a port

## Low Severity Events

### System Information
- **4608**: Windows is starting up
- **4609**: Windows is shutting down
- **4610**: Authentication package loaded
- **4611**: Trusted logon process registered
- **4612**: IPsec Services started
- **4614**: Notification package loaded
- **4622**: Security package loaded
- **4904**: Security event source added

### Routine Operations
- **4656**: Object handle requested
- **4658**: Handle to object closed
- **4661**: Handle to object requested
- **4662**: Operation performed on object
- **4673**: Privileged service called
- **4674**: Operation attempted on privileged object
- **4675**: SIDs were filtered
- **4945**: Rule listed when Windows Firewall started

### Audit & Logging
- **4902**: Per-user audit policy table created
- **4907**: Auditing settings on object changed
- **4908**: Special Groups table modified
- **4912**: Per-user audit policy changed
- **5024**: Windows Firewall started
- **5033**: Windows Firewall Driver started
- **5034**: Windows Firewall Driver stopped

## Event Categories

### Log Types
1. Security
2. System
3. Application
4. Setup
5. Network
6. PowerShell
7. Windows Defender
8. Active Directory

### Event Sources
1. Windows Security
2. Windows System
3. Windows Application
4. Windows PowerShell
5. Microsoft-Windows-Security-Auditing
6. Microsoft-Windows-Windows Defender
7. Microsoft-Windows-NetworkProfile
8. Microsoft-Windows-GroupPolicy

## Alert Response Actions

### High Severity
- Immediate notification to security team
- Automatic incident ticket creation
- Real-time alerts to administrators
- Logging of all related events
- Automatic containment measures where applicable

### Medium Severity
- Notification to system administrators
- Incident logging
- Pattern analysis
- Scheduled review

### Low Severity
- Event logging
- Periodic review
- Pattern analysis for potential escalation

## Monitoring Recommendations

1. **Real-time Monitoring**
   - High severity events
   - Authentication failures
   - System changes
   - Network security events

2. **Periodic Monitoring**
   - Medium severity events
   - System performance
   - User activity patterns
   - Resource usage

3. **Batch Monitoring**
   - Low severity events
   - Routine operations
   - System information
   - Audit logs

## Best Practices

1. **Event Collection**
   - Enable audit policies for all relevant event categories
   - Configure appropriate log sizes
   - Implement log rotation
   - Set up secure log forwarding

2. **Alert Management**
   - Define clear escalation procedures
   - Set up notification channels
   - Implement alert correlation
   - Regular review of alert thresholds

3. **Response Procedures**
   - Document response procedures for each severity level
   - Regular testing of response procedures
   - Maintain updated contact information
   - Regular training for response teams 