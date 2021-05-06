#Example here: create a XML file for adding/removing devices from a smart group.
#change as you need.

function Create-XMLBodyFile
{
param(
        $DeviceInformation, 
        [string] $TempFile,
        [string] $SmartGroupName,
        [string] $SmartGroupID,
        [string] $SmartGroupUuid,
        [string] $CriteriaType,
        [string] $ManagedByOrganizationGroupId,
        [string] $ManagedByOrganizationGroupUUID,
        [string] $ManagedByOrganizationGroupName
    )

#XML setting definition  
$xmlWriter = new-object system.xml.xmltextwriter($TempFile,[System.Text.Encoding]::UTF8)
$xmlWriter.Formatting = 'Indented'
$xmlWriter.Indentation = 1
$XmlWriter.IndentChar = "`t"

#Start root XML hive
$xmlWriter.WriteStartDocument()
$xmlWriter.WriteStartElement('SmartGroup')
$xmlWriter.WriteAttributeString('xmlns:xsd','http://www.w3.org/2001/XMLSchema')
$xmlWriter.WriteAttributeString('xmlns:xsi','http://www.w3.org/2001/XMLSchema-instance')
$xmlWriter.WriteAttributeString('xmlns','http://www.air-watch.com/servicemodel/resources')

#Add SmartGroup settings
$xmlWriter.WriteElementString('Name',$SmartGroupName)
$xmlWriter.WriteElementString('SmartGroupID',$SmartGroupID)
$xmlWriter.WriteElementString('SmartGroupUuid',$SmartGroupUuid)
$xmlWriter.WriteElementString('CriteriaType',$CriteriaType)
$xmlWriter.WriteElementString('ManagedByOrganizationGroupId',$ManagedByOrganizationGroupId)
$xmlWriter.WriteElementString('ManagedByOrganizationGroupUuid',$ManagedByOrganizationGroupUuid)
$xmlWriter.WriteElementString('ManagedByOrganizationGroupName',$ManagedByOrganizationGroupName)

#Add devices to Smartgroup rule
$xmlWriter.WriteStartElement('DeviceAdditions')

foreach($device in $DeviceInformation.GetEnumerator())
{
$xmlWriter.WriteStartElement('Device')
$xmlWriter.WriteElementString('Id',$device.Name)

$xmlWriter.WriteElementString('Name',$device.Value)
$xmlWriter.WriteEndElement()
}

#Close the XML and save it to the file
$xmlWriter.WriteEndElement()
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()

}

Create-XMLBodyFile -DeviceInformation $DeviceIDsTable -TempFile $XMLTempFile -SmartGroupName $response.Name -SmartGroupID $response.SmartGroupID -SmartGroupUuid $response.SmartGroupUuid -CriteriaType $SmartGroupType -ManagedByOrganizationGroupId $response.ManagedByOrganizationGroupId -ManagedByOrganizationGroupUUID $response.ManagedByOrganizationGroupUuid -ManagedByOrganizationGroupName $response.ManagedByOrganizationGroupName
$Body = Get-Content $XMLTempFile
