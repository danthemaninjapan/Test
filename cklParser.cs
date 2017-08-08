using System;
using System.IO;
using System.Data;
using System.Collections;
using System.Text;
using System.Xml;

/*  Background: 
 *  
 *  The US Department of Defense produces a collection of security hardening guides for various products (OS, web servers, network appliances, etc) 
 *  called Security Technical Implementation Guidelines (STIGs), in concert with NSA, CERT, software vendors (i.e. Microsoft), and other security organizations.  
 *  
 *  For example, here's the web server section of that collection:
 *  http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
 *  They also have tools used to assist with scanning for STIG compliance -- SCAP benchmark scanner -- and documentation of compliance status -- STIG Viewer, 
 *  which creates checklists based on STIG content for easy review by cybersecurity inspection teams.  An individual vulnerability check might be setting a 
 *  Windows registry value to disable legacy SSL support, ensuring services/applications are being run with minimum required permissions, strong encryption 
 *  is being used for data in transit / data at rest, and so on.
 */

/*  CKLParser
 *  Used to migrate content (vuln status, fix actions applied, etc) from STIG Viewer checklists (XML data) when a new version of the STIG is released 
 *  (i.e.the Windows Server 2008R2 STIG was updated several times in the last year, and contains about 300 different vulnerability checks which would need
 *  to be migrated after each update).  Doing so from within the STIG Viewer UI is a time-consuming manual process(many thousands of entries for our environment), 
 *  so this tool will automatically extract the important data from the old checklist and copy it into the updated one in just a few seconds.
 */

namespace cklParser
{
    class cklParser_Main
    {
        static Hashtable htDeviceInfo = new Hashtable();
        static Hashtable htVulns = new Hashtable();
        static XmlDocument oldFile;
        static XmlDocument newFile;
       
        static void Main(string[] args)
        {
            if (args.Length == 2 && CheckFiles(args))
            {
                LoadOldData();
                CompareOldToNew(args[0]);
            }
            else
            {
                Console.WriteLine("Migrates old STIG Viewer Checklist content to new versions.");
                Console.WriteLine("cklParser.exe [in] [out] ");
                Console.WriteLine("-[in]\t Input .ckl filename");
                Console.WriteLine("-[out]\t Ouptut .ckl filename.  Use a new, blank .ckl file exported from STIG Viewer.");
                Console.WriteLine("Ex:\tcklParser.exe win7.ckl win7_new.ckl");
            }
        }

        private static Boolean CheckFiles(string[] args)
        {
            bool filesLoaded = true;
            try
            {
                oldFile = new XmlDocument();
                oldFile.Load(args[0]);
            }
            catch (Exception ex)
            {
                filesLoaded = false;
                Console.WriteLine("An error occurred when attempting to load input file: {0}", args[0]);
            }
            try
            {
                newFile = new XmlDocument();
                newFile.Load(args[1]);
            }
            catch (Exception ex)
            {
                filesLoaded = false;
                Console.WriteLine("An error occurred when attempting to load output file: {0}", args[1]);
            }
            return filesLoaded;
        }


	// Extract the old checklist file metadata and contents and load each XML node containing vulnerability info into a hashtable with the Vulnerability ID as the key
        private static void LoadOldData()
        {
            
            XmlNode oldRoot     = oldFile.DocumentElement;

            XmlNode assetType   = oldRoot.SelectSingleNode("/CHECKLIST/ASSET/ASSET_TYPE");
            XmlNode hostname    = oldRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_NAME");
            XmlNode IPAddress   = oldRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_IP");
            XmlNode MACAddress  = oldRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_MAC");
            XmlNode hostGUID    = oldRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_GUID");
            XmlNode hostFQDN    = oldRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_FQDN");
            XmlNode techArea    = oldRoot.SelectSingleNode("/CHECKLIST/ASSET/TECH_AREA");
            XmlNode targetKey   = oldRoot.SelectSingleNode("/CHECKLIST/ASSET/TARGET_KEY");
            
            
            htDeviceInfo.Add("assetType", assetType);
            htDeviceInfo.Add("hostname", hostname);
            htDeviceInfo.Add("IPAddress", IPAddress);
            htDeviceInfo.Add("MACAddress", MACAddress);
            htDeviceInfo.Add("hostGUID", hostGUID);
            htDeviceInfo.Add("hostFQDN", hostFQDN);
            htDeviceInfo.Add("techArea", techArea);
            htDeviceInfo.Add("targetKey", targetKey);

            XmlNodeList allVulns = oldRoot.SelectNodes("/CHECKLIST/STIGS/iSTIG/VULN");  // This is the node that contains each vulnerability check
            Console.WriteLine("LoadOldData:  Found {0}", allVulns.Count.ToString());
            foreach (XmlNode node in allVulns)
            {
                Hashtable NodesToCopy = new Hashtable();

                XmlNode status          = node.SelectSingleNode("STATUS"); // <STATUS />
                XmlNode findingDetails  = node.SelectSingleNode("FINDING_DETAILS"); //<FINDING_DETAILS />
                XmlNode comments        = node.SelectSingleNode("COMMENTS"); //<COMMENTS />
                XmlNode vulnNumXML      = node.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Vuln_Num']]"); // STIG_DATA->Vuln_Num
                XmlNode ruleIDXML       = node.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Rule_ID']]"); // STIG_DATA->Rule_ID
                XmlNode STIGIDXML       = node.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Rule_Ver']]"); // STIG_DATA->STIG_ID
                XmlNode discussion      = node.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Vuln_Discuss']]"); // STIG_DATA->Vuln_Discuss
                XmlNode checkContent    = node.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Check_Content']]"); // STIG_DATA->Check_Content
                XmlNode fixText         = node.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Fix_Text']]"); // STIG_DATA->Fix_Text*/
                String vulnNum          = vulnNumXML.SelectSingleNode("ATTRIBUTE_DATA").InnerText;
                String ruleID           = ruleIDXML.SelectSingleNode("ATTRIBUTE_DATA").InnerText;
                String STIGID           = STIGIDXML.SelectSingleNode("ATTRIBUTE_DATA").InnerText;


                NodesToCopy.Add("status", status);
                NodesToCopy.Add("findingDetails", findingDetails);
                NodesToCopy.Add("comments", comments);
                NodesToCopy.Add("vulnNum", vulnNumXML);
                NodesToCopy.Add("discussion", discussion);
                NodesToCopy.Add("checkContent", checkContent);
                NodesToCopy.Add("fixText", fixText);

                if (htVulns.Contains(vulnNum))
                {
                    Console.WriteLine(String.Format("{0}: ignoring duplicate entry.", vulnNum));
                }
                else
                {
                    htVulns.Add(vulnNum, NodesToCopy);
                }
                
            }
        }

	/* Populate the host metadata and loop through data extracted from the old checklist.  Copy the old checklist's data to the new, 
	blank checklist, and notify if any vulnerability checks are duplicated or missing in the new version.  Write results to [input filename].log */
	
        private static void CompareOldToNew(string outputFile)
        {
            XmlNode newRoot = newFile.DocumentElement;
            StringBuilder logBuffer = new StringBuilder();


            XmlNode newAssetType    = newRoot.SelectSingleNode("/CHECKLIST/ASSET/ASSET_TYPE");
            XmlNode oldAssetType    = htDeviceInfo["assetType"] as XmlNode;
            newAssetType.InnerText  = oldAssetType.InnerText;

            XmlNode newHostname     = newRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_NAME");
            XmlNode oldHostname     = htDeviceInfo["hostname"] as XmlNode;
            newHostname.InnerText   = oldHostname.InnerText;

            XmlNode newIPAddress    = newRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_IP");
            XmlNode oldIPAddress    = htDeviceInfo["IPAddress"] as XmlNode;
            newIPAddress.InnerText  = oldIPAddress.InnerText;

            XmlNode newMACAddress   = newRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_MAC");
            XmlNode oldMACAddress   = htDeviceInfo["MACAddress"] as XmlNode;
            newMACAddress.InnerText = oldMACAddress.InnerText;

            XmlNode newHostGUID     = newRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_GUID");
            XmlNode oldHOSTGUID     = htDeviceInfo["hostGUID"] as XmlNode;
            newHostGUID.InnerText   = oldHOSTGUID.InnerXml;
            
            
            XmlNode newHostFQDN     = newRoot.SelectSingleNode("/CHECKLIST/ASSET/HOST_FQDN");
            XmlNode oldHostFQDN     = htDeviceInfo["hostFQDN"] as XmlNode;
            newHostFQDN.InnerText   = oldHostFQDN.InnerXml;

            XmlNode newTechArea     = newRoot.SelectSingleNode("/CHECKLIST/ASSET/TECH_AREA");
            XmlNode oldTechArea     = htDeviceInfo["techArea"] as XmlNode;
            newTechArea.InnerText   = oldTechArea.InnerText;

            XmlNode newTargetKey    = newRoot.SelectSingleNode("/CHECKLIST/ASSET/TARGET_KEY");
            XmlNode oldTargetKey    = htDeviceInfo["targetKey"] as XmlNode;
            newTargetKey.InnerText  = oldTargetKey.InnerText;
            

            XmlNodeList allVulns = newRoot.SelectNodes("/CHECKLIST/STIGS/iSTIG/VULN");

            Console.WriteLine("CompareOldToNew: found {0}", allVulns.Count.ToString());
            
            int transferred = 0;
            int skipped = 0;
            int changed = 0;

            foreach (DictionaryEntry item in htVulns)
            {
                Hashtable oldValues = htVulns[item.Key] as Hashtable;
                XmlNode thisNode = newRoot.SelectSingleNode("/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA[ATTRIBUTE_DATA[text()='" + item.Key + "']]]");

                
                if (thisNode == null) // Old VulID doesn't exist in the new checklist, skip and leave marked as Not Reviewed
                {
                    logBuffer.AppendLine(String.Format("VulID {0} not found in new checklist.  Skipping...", item.Key));
                    skipped++;
                }
                else
                {
                    
                    XmlNode oldCheckContent = oldValues["checkContent"] as XmlNode;
                    XmlNode newCheckContent = thisNode.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Check_Content']]");
                    XmlNode oldFixText = oldValues["fixText"] as XmlNode;
                    XmlNode newFixText = thisNode.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Fix_Text']]");
                    XmlNode oldDiscussion = oldValues["discussion"] as XmlNode;
                    XmlNode newDiscussion = thisNode.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE[text()='Vuln_Discuss']]");
                    try
                    {
                        bool ChangeFound = false;

                        if (oldCheckContent.ChildNodes[1].InnerText.ToUpper().Replace(" ", "").Equals(newCheckContent.ChildNodes[1].InnerText.ToUpper().Replace(" ", "")))
                        {
                            Console.WriteLine(item.Key + " Check_Content: no change.");
                            logBuffer.AppendLine(item.Key + " Check_Content: no change.");
                        }
                        else
                        {
                            Console.WriteLine(item.Key + " Check_Content: value changed.");
                            logBuffer.AppendLine(item.Key + " Check_Content: value changed.");
                            logBuffer.AppendLine("Old Value:\n" + oldCheckContent.ChildNodes[1].InnerText);
                            logBuffer.AppendLine("New Value:\n" + newCheckContent.ChildNodes[1].InnerText);
                            ChangeFound = true;
                        }

                        if (oldFixText.ChildNodes[1].InnerText.ToUpper().Replace(" ", "").Equals(newFixText.ChildNodes[1].InnerText.ToUpper().Replace(" ", "")))
                        {
                            Console.WriteLine(item.Key + " Fix_Text: no change.");
                            logBuffer.AppendLine(item.Key + " Fix_Text: no change.");
                        }
                        else
                        {
                            Console.WriteLine(item.Key + " Fix_Text: value changed.");
                            logBuffer.AppendLine(item.Key + " Fix_Text: value changed.");
                            logBuffer.AppendLine("Old Value:\n" + oldFixText.ChildNodes[1].InnerText);
                            logBuffer.AppendLine("New Value:\n" + newFixText.ChildNodes[1].InnerText);
                            ChangeFound = true;
                        }
                        if (oldDiscussion.ChildNodes[1].InnerText.ToUpper().Replace(" ", "").Equals(newDiscussion.ChildNodes[1].InnerText.ToUpper().Replace(" ", "")))
                        {
                            Console.WriteLine(item.Key + " Vuln_Discuss: no change.");
                            logBuffer.AppendLine(item.Key + " Vuln_Discuss: no change.");
                        }
                        else
                        {
                            Console.WriteLine(item.Key + " Vuln_Discuss: value changed.");
                            logBuffer.AppendLine(item.Key + " Vuln_Discuss: value changed.");
                            logBuffer.AppendLine("Old Value:\n" + oldDiscussion.ChildNodes[1].InnerText);
                            logBuffer.AppendLine("New Value:\n" + newDiscussion.ChildNodes[1].InnerText);
                            ChangeFound = true;
                        }

                        if (ChangeFound)
                        {
                            XmlNode newStatus = thisNode.SelectSingleNode("STATUS");
                            newStatus.InnerText = "Not_Reviewed";
                            changed++;
                        }
                        else
                        {
                            XmlNode newStatus = thisNode.SelectSingleNode("STATUS");
                            XmlNode oldStatus = oldValues["status"] as XmlNode;
                            newStatus.InnerText = oldStatus.InnerText;
                        }
                        XmlNode newFindingDetails = thisNode.SelectSingleNode("FINDING_DETAILS");
                        XmlNode oldFindingDetails = oldValues["findingDetails"] as XmlNode;
                        newFindingDetails.InnerText = oldFindingDetails.InnerText;

                        XmlNode newComments = thisNode.SelectSingleNode("COMMENTS");
                        XmlNode oldComments = oldValues["comments"] as XmlNode;
                        newComments.InnerText = oldComments.InnerText;
                        transferred++;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("An error occurred while processing Vuln ID {0}./nDetails{1}", oldValues["vulnNum"].ToString(), ex.Message);
                    }
                }
                
            }
            Console.WriteLine("Transferred {0} items.  {1} changes. {2} items were not found in the new checklist.", transferred.ToString(), changed.ToString(), skipped.ToString());
            logBuffer.AppendLine(String.Format("Transferred {0} items.  {1} changes. {2} items were not found in the new checklist.", transferred.ToString(), changed.ToString(), skipped.ToString()));

            newFile.Save("UPDATED_" + outputFile);
            File.WriteAllText(outputFile + ".log", logBuffer.ToString());
        }
    }
}
