<?php  //test.php

include(dirname(__FILE__).'/inc.inc.php'); //master include file 


$username = 'mike'; 
$authHosts = array(); 
$authServices = array(); 
$authHostgroups = array(); 
$authServicegroups = array(); 



//fetch necessary object config arrays 
$hosts = $NagiosData->getProperty('hosts_objs');
$contactgroups = $NagiosData->getProperty('contactgroups'); 


$cg_memberships = array(); 

//find relevant contact groups for user 
foreach($contactgroups as $cg)
{
	//echo $cg['contactgroup_name']; 
	if(strpos($cg['members'],$username)!==false) 
		$cg_memberships[] = $cg['contactgroup_name']; 			
}

//echo "CG Memberships<br />"; 
//print_r($cg_memberships); 

//check host for host->contact and host->contactgroup relationships 

//////////////CREATE SINGLE MULTI-D HEIRARCHY ARRAY 
/*
//	$authObjects = 
	array ( 'localhost'	array(
//										'host_name' => 'localhost'
//										'services'	=> array( 0 => service1
																	 1 => service2
																	 3 => service3 )
//										) 
*/


foreach($hosts as $host)
{
	$key = $host['host_name']; 
	if(isset($host['contacts']) && strpos($host['contacts'],$username) !== false)
	{
		if(!isset($authHosts[$key])) $authHosts[$key] = array('host_name' => $key, 'services' => array() ); 
		$authHosts[$key['host_name']] = $key; 
		continue; //skip to next 
	}	
	if(isset($host['contact_groups']))
	{
		$cgmems = explode(',',$host['contact_groups']);
		foreach($cgmems as $cg)
		{
			if(in_array($cg,$cgmems)) 
			{
				$authHosts[$key['host_name']] = $key; 
				break; 
			}	//end IF
		
		}	//end FOREACH contactgroup member
	}//end IF contactgroups set 	

}//end FOREACH host 


$services = $NagiosData->getProperty('services_objs');

//echo "Services: <br /><pre>".print_r($services,true)."</pre>"; 

foreach($services as $service)
{
	$auth = false; 
	$key = $service['host_name']; 
	//check for authorized host first, if host is authorized add services  
	if(array_key_exists($key,$authHosts)) 
	{
		if(!isset($authHosts[$key])) $authHosts[$key] = array('host_name' => $key, 'services' =>array() ); 
		if(!isset($authHosts[$key]['services'])) $authHosts[$key['services']] = array(); 
		//$authHosts[$key['services'][]] = $service['service_description']; 
		//echo $authHosts[$key['services']]; 
		array_push($authHosts[$key['services']], $service['service_description']); 
		//$authServices[$service['host_name']] = 	
	}
	
	//check for authorization at the service level 
	if(isset($service['contacts']) && strpos($service['contacts'],$username) !== false)
	{
		if(!isset($authHosts[$key])) $authHosts[$key] = array(); 
		array_push($authHosts[$key['services']], $service['service_description']); 
		continue; 
	}
	//check agains contactgroups 
	if(isset($service['contact_groups']) )
	{
		$cgmems = explode(',',$service['contact_groups']);
		foreach($ch_memberships as $cg)
		{
			if(in_array($cg,$cgmems)) 
			{
				array_push($authHosts[$key['services']],$service['service_description']);
				break; 
			}	//end IF		
		}	//end FOREACH contactgroup member			
	} //end IF contactgroups 
} //end services FOREACH 






echo "<br />Auth hosts:<br />";  
echo "<pre>".print_r($authHosts,true)."</pre>"; 


function is_authorized_for_host($username,$host)
{
	global $NagiosData; 
	
	

}

?>