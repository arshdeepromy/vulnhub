<?php
/**
 * Knowledge base for turning an install path into a product name.
 *
 * The old rule was "take the nearest meaningful folder above the file", which
 * is wrong far more often than it looks: the folder nearest the file is nearly
 * always structural. Real examples from this estate, and what they produced:
 *
 *   ...\AppData\Roaming\Zoom\tmp_bin\libcurl.dll                -> "Tmp_bin"
 *   ...\Program Files (x86)\SQL\sqldeveloper\sqldeveloper\lib\   -> "SQL"
 *   ...\WindowsApps\Microsoft.Todos_2.176.7601.0_x64__...\       -> "Todos"
 *   ...\Microsoft\Edge\Application\152.0\undocked_copilot\       -> "Deleted"
 *   /u01/jde920/e920/system/bin64/openssl                        -> "Jde920"
 *   /u01/clone/dev/mwhome/SOA12.2.1.4/oracle_common/modules/     -> "Clone"
 *   /var/app/current/webtier-1.0.9.jar                           -> "current"
 *
 * Three lists do the work. STRUCTURE names directories that exist in every
 * install and therefore never name a product. ANCHORS recognises a vendor's
 * own layout, which is the only reliable way to read a deployment root like
 * `jde920` or `SOA12.2.1.4`. ALIASES maps what is on disk to what the product
 * is called.
 *
 * Anything not resolved is left empty on purpose. A finding with no product is
 * honest and shows up as unattributed; a finding labelled "Configuration" is a
 * fake row in the exposure widget that somebody has to waste time on.
 *
 * @package VulnHub
 */

return array(

	/* =================================================================
	 * Directories that are part of an install, not the name of one.
	 *
	 * Matched case-insensitively against a whole path segment.
	 * ============================================================== */
	'structure' => array(
		// Filesystem and OS roots.
		'c', 'd', 'e', 'usr', 'opt', 'var', 'srv', 'etc', 'home', 'root', 'mnt',
		'media', 'export', 'local', 'users', 'documents and settings',
		'program files', 'program files (x86)', 'programdata', 'appdata',
		'roaming', 'locallow', 'windows', 'winsxs', 'system32', 'syswow64',
		'u01', 'u02', 'u03', 'u04', 'app', 'apps', 'application', 'applications',

		// Build and runtime layout.
		'bin', 'bin64', 'sbin', 'lib', 'lib64', 'libs', 'libexec', 'include',
		'share', 'modules', 'module', 'plugins', 'plugin', 'packages', 'package',
		'thirdparty', 'third_party', 'vendor', 'node_modules', 'jre', 'jdk',
		'jlib', 'classes', 'conf', 'config', 'configuration', 'settings',
		'resources', 'assets', 'static', 'public', 'webapps', 'war', 'ear',
		'dist', 'build', 'target', 'out', 'obj', 'debug', 'release', 'releases',
		'current', 'latest', 'stable', 'active', 'default', 'shared', 'common',
		'common files', 'core', 'runtime', 'engine', 'server', 'client',
		'internal', '_internal', 'utilities', 'utils', 'tools', 'toolkit',
		'files', 'file', 'data', 'db', 'database', 'logs', 'log', 'cache',
		'temp', 'tmp', 'tmp_bin', 'scratch', 'work', 'workspace', 'staging',
		'stage', 'patches', 'patch', 'binary_patches', 'software', 'installers',
		'installer', 'setup', 'download', 'downloads', 'backup', 'backups',
		'old', 'new', 'copy', 'clone', 'deleted', 'archive', 'archived',
		'product', 'products', 'system', 'sysman', 'targets', 'target_home',
		'instances', 'instance', 'domains', 'domain', 'user_projects',
		'oracle_common', 'oracle_home', 'middleware', 'mwhome', 'oms',
		'inventory', 'orainventory', 'gridhome', 'grid', 'network', 'admin',
		'sql', 'scripts', 'script', 'src', 'test', 'tests', 'todos', 'parser',
		'generic', 'x64', 'x86', 'amd64', 'win32', 'win64', 'solaris_sparc64',
		'linux', 'windows_x64', 'suptools', 'undocked_copilot',
	),

	/* =================================================================
	 * Vendor layouts. The first match against the whole path wins, so
	 * the more specific pattern comes first.
	 *
	 * Each entry is a regex tested against the path with separators
	 * normalised to "/", and the product it means.
	 * ============================================================== */
	'anchors' => array(
		// --- Oracle, whose deployment roots are never the product name ---
		'#/jde[_-]?home#i'                        => 'Oracle JD Edwards',
		'#/jde\d|/e9\d\d(/|$)#i'                  => 'Oracle JD Edwards',
		'#/(soa|osb)[_-]?(suite|spb)?\d#i'        => 'Oracle SOA Suite',
		'#/wlserver|/weblogic#i'                  => 'Oracle WebLogic Server',
		'#/coherence#i'                           => 'Oracle Coherence',
		'#/(ohs|oracle\.ohs)#i'                   => 'Oracle HTTP Server',
		'#/agent\d+c(/|$)|/agent_\d|/sysman#i'    => 'Oracle Enterprise Manager Agent',
		'#/grid(home)?[_/]|/gridhome#i'           => 'Oracle Grid Infrastructure',
		'#/orachk|/oracle\.ahf|/ahf(/|$)#i'       => 'Oracle Autonomous Health Framework',
		'#/(db|dbhome)_\d|/rdbms/#i'              => 'Oracle Database',
		'#/sqldeveloper#i'                        => 'Oracle SQL Developer',

		// --- Windows app layouts ---
		'#/Microsoft/Edge/#i'                     => 'Microsoft Edge',
		'#/Microsoft/EdgeWebView#i'               => 'Microsoft Edge WebView2',
		'#/Microsoft Office|/Office1[5-9]#i'      => 'Microsoft Office',
		'#/Microsoft SQL Server#i'                => 'Microsoft SQL Server',
		'#/Microsoft Visual Studio#i'             => 'Microsoft Visual Studio',

		// --- Other vendors seen in this estate ---
		'#/\.katalon|/Katalon#i'                  => 'Katalon Studio',
		'#/Commvault|/Simpana#i'                  => 'Commvault',
		'#/tomcat#i'                              => 'Apache Tomcat',
		'#/(apache-)?jmeter#i'                    => 'Apache JMeter',
		'#/workspace-sts|/springsource|/sts-\d#i' => 'Spring Tool Suite',
		'#/nessus#i'                              => 'Tenable Nessus',
		'#/zoom(/|$)#i'                           => 'Zoom',
		'#/gdal#i'                                => 'GDAL',
	),

	/* =================================================================
	 * What the thing on disk is actually called.
	 *
	 * Keyed on the lower-cased, punctuation-stripped folder name, so
	 * "sqldeveloper_23", "SQLDeveloper" and "sql-developer" all land on
	 * the same entry.
	 * ============================================================== */
	'aliases' => array(
		'sqldeveloper'            => 'Oracle SQL Developer',
		'jdeveloper'              => 'Oracle JDeveloper',
		'dataloader'              => 'Salesforce Data Loader',
		'awscliv2'                => 'AWS CLI',
		'awscli'                  => 'AWS CLI',
		'log4jcore'               => 'Apache Log4j',
		'springcore'              => 'Spring Framework',
		'commonsfileupload'       => 'Apache Commons FileUpload',
		'edgecore'                => 'Microsoft Edge',
		'microsoftedgecore'       => 'Microsoft Edge',
		'crossdevice'             => 'Microsoft Phone Link',
		'zoomvdipluginmanagement' => 'Zoom',
		'soapui'                  => 'SoapUI',
		'passwordmanagerpro'      => 'ManageEngine Password Manager Pro',
		'pmp'                     => 'ManageEngine Password Manager Pro',
		'katalonstudio'           => 'Katalon Studio',
		'powerbidesktop'          => 'Microsoft Power BI Desktop',
		'sikulix'                 => 'SikuliX',
		'compareplus'             => 'ComparePlus',
		'apowermirror'            => 'ApowerMirror',
		'spectrumspatialanalyst'  => 'Precisely Spectrum Spatial Analyst',
		'hptelemetry'             => 'HP Telemetry',
		'hponeagent'              => 'HP One Agent',
		'mysqlworkbench'          => 'MySQL Workbench',
		'gdal'                    => 'GDAL',
	),
);
