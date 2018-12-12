Step 1:
Create an Service Account in your Active Directory domain.
This service account needs an UPN suffix with a verified Office 365 domain.

For example: It can be user1@contoso.com, but cannot be user1@contoso.local.
Where contoso.com is added as a verified domain in Office 365.

Sync your Active Directory domain with Azure AD (it normally does every 30 minutes automatically).
Also make sure the Service Account has read-rights in your Active Directory.

Step 2:
Go to Office 365 and add an Office 365 license to the Service Account (with the Teams subscription).

Step 3:
Go to teams.microsoft.com and add the service account as an owner of the Teams you want to manage from AD.

Step 4:
Add the users of the Teams you want to manage to the AD groups you want to sync.

Step 5:
Add AD Groupname and Team name you want to sync to Teams.csv (example csv is in the zip-file), with a comma as a delimiter.
Every line is an Active Directory group and Team that needs to be synced.

WARNING: MAKE SURE YOU ADD ALL MEMBER USERS THAT ARE CURRENTLY IN THE TEAM TO THE RESPECTIVE AD GROUP, ALL MEMBERS THAT ARE IN THE TEAM BUT AREN'T THE AD GROUP ARE REMOVED FROM THE TEAM.
WITH AN EXCEPTION OF OWNERS OFFCOURSE.

Step 6:
Run Powershell as the service user and browse to the location.
run Set-SecureTeamUserInfo.ps1 and type in the credentials of the service account (UserPrincipalName, not SamAccountName).
Credentials are now securely saved in the folder so the script can sign in to Office 365.

---

You now manage your Microsoft Team using Active Directory groups.