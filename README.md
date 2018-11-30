# sccd
Security Code Clone Detection
v01


Minimum System Requirements
--------------------------------------------------
Eclipse-Version: Oxygen.3 Release (4.7.3)
Java-Version: 1.8.0_171 





(i) Extract Security Repository
--------------------------------------------------
Extract the zip file "sec-repo/sec-repo.zip"



(ii) Plugin Installation
--------------------------------------------------
1. Copy the jar file "jar/de.luh.se.sccd.plugin_1.0.0.1.jar" into the plugins folder of your Eclipse instance.
2. Add the following line without the quotes to your bundles.info file
   "de.luh.se.sccd.plugin,1.0.0.1,plugins/de.luh.se.sccd.plugin_1.0.0.1.jar,4,false"
3. Start Eclipse



(iii) Setup Plugin
--------------------------------------------------
1. After Eclipse has started goto Window->Preferences->General->SCC Detector
2. Set Clone Detector Output Directory and the Settings Directory to an existing folder
3. Add the path to the security repository from (i)
4. Add valid values for Auto Scan Interval and Minimum File Bytes Changed
5. Click Apply and Close an restart Eclipse



(iv) Copy Evaluation Project to Workspace
--------------------------------------------------
1. Copy the SCCD_TestJavaProject project into your Eclipse workspace
2. Import project to your into Eclipse



(v) Start Clone Detection
--------------------------------------------------
1. Goto SCC Detector->Process Security Repository
2. Open one of the source files from project SCCD_TestJavaProject
3. Goto SCC Detector->Scan File

