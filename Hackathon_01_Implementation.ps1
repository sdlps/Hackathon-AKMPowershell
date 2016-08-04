## KC2016 - Implementation


###############################################################################################################################

# Our Case for customer environment:
#      1. Create LOVs
#       2. Create Fields
#       3. Add to lists
#       3. Add Search Fields
#       4. Add User-Group
#       5. Add User-Roles
#       6. Add Workflow-state
#       7. Add StatusTransition
#       8. Add Inbox Actions
#       9. Add workflow report
#       10. Add Translation report
#       11. Translation configuration
#       12. Create Output formats
#       13. Batch Import configuration


################################################################################################################################

Import-Module servermanager
$module = Get-Module servermanager
$module.exportedCmdlets


################################################################################################################################
#	Create LOVs

Create-LOV -id "DDHMARKET" -label "Market" -Description "Market" -value @(VDHCONAD="conad"; VDHCRV="crv")

################################################################################################################################
#	Create Fields
Create-Field -id "FDHMARKET" -label "Market" -Description "Market" -Mandatory $false -Multivalue $false -LOV "DDHMARKET" -Language "lng" -ObjectType "topic"

################################################################################################################################
#	Add to lists
Add-ViewList -Field "FDHMARKET" -Type @("inbox", "version", "repository", "publicationoutput")

################################################################################################################################
#	Add to lists
Add-Search -Field "FDHMARKET" -WhereToAdd @("client", "web") Label "Market" -Sort $true -Hidden $false -Assist $true -Description ""

################################################################################################################################
#	Add to User group
Add-UserGroup -Name "NewGroup" -Description "New Group"

################################################################################################################################
#	Add to User role
Add-UserRole -Name "NewRole" -Description "New Role"

################################################################################################################################
#	Add to status transitions
Add-StatusTransition -Source "ToBeReviewed" -Target "Reviewed"
Add-StatusTransition -Source "ToBeReviewed" -Target "Draft"

################################################################################################################################
#	Add-OutputFormat
Add-OutputFormat -OutputFormatName "" -Resolutions "" -EDTOutput "" -TransType "" -StyleProcessor "" -SingleFile $true -Cleanup $false

###############################################################################################################################
#	Push EnterVIAUI configuration files to database
#   e.g. Admin.XMLInboxConfiguration.xml
Push-EnterViaUI
 