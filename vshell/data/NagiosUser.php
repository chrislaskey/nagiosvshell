<?php //NagiosUser.php  nagios user class to handle authorized hosts, services, and admin functionality 




class NagiosUser
{	
	//boolean for users who can see and access all features 
	protected $admin = false; 
	//boolean for viewing all hosts and services 
	protected $sees_all = false; 

	//array for storing global authorizations from cgi file
	protected $authKeys = array(
		'authorized_for_all_host_commands' => false,
		'authorized_for_all_hosts' => false,
		'authorized_for_all_service_commands' => false,
		'authorized_for_all_services' => false,
		'authorized_for_configuration_information' => false,
		'authorized_for_system_commands' => false,
		'authorized_for_system_information' => false,
		'authorized_for_read_only' => true,	
		);
		
	//MAIN AUTH ARRAY 
	protected $authHosts = array(); //see below for array structure 
	/*
		$authHosts = 
		array ( 'localhost' => array(
											'host_name' => 'localhost',
											'all_services' => true | false, 
											'services'	=> array( 0 => service1
																		 1 => service2
																		 3 => service3 
																		 )
											) 
	*/
	protected $cg_memberships = array(); //contactgroup memberships 
	protected $username; 
		
	//constructor 
	//initialize authorized hosts and services only upon construction and then (@TODO)cache data 
	//TODO move towards session auth so this info gets updated upon login and restart of Nagios 	
	function __construct($username=false) {
		//some users have requested to turn off authentication or user other methods, this allows override and backwards compatibility 
		if(!$username)
			$this->username = $this->get_user(); 
		else $this->username = $username; //for users that hard-code a username: NOT RECOMMENDED  
		
		//build main authKeys array (cgi.cfg settings) 
		$this->set_perms(); 
		//check if user can see everything 
		$this->admin = $this->determine_admin(); 

		//if user level account, determin authorized objects for object filtering 
		if(!$this->admin) {
			//check fo see if user can see all hosts and services 
			$this->sees_all = ($this->authKeys['authorized_for_all_hosts'] == true && $this->authKeys['authorized_for_all_services']) ? true : false; 
			//build auth objects array 
			$this->build_authorized_objects(); 
		}
		//print_r($this->authHosts); 
	
	}
	
	private function get_user()
	{	
		global $username;
		//allow for basic auth override for backwards compatibility with early versions of V-Shell 
		if($username) return $username; //TODO: eventually this will be removed, and auth will not be optional 
		 
		// HTTP BASIC AUTHENTICATION through Nagios Core or XI 
		//$remote_user="";
		if(isset($_SERVER["REMOTE_USER"]))
		{	
			$remote_user=$_SERVER["REMOTE_USER"];
			//echo "REMOTE USER is set: $remote_user<br />";
			return $remote_user;
		}
		//digest authentication 
		elseif(isset($_SERVER['PHP_AUTH_USER']))
		{
			//echo "Auth Digest detected".$_SERVER['PHP_AUTH_USER'];
			return $_SERVER['PHP_AUTH_USER'];
		}
		else
		{
			echo "Access Denied: No authentication detected.";
			return false; 
		}	
	 
	}	
	
	////////////////////////////////////////////////////////////
	//$username is obtained from $_SERVER authorized user for nagios 
	//TODO: make this better.  All auth stuff needs to be handled here, no more global authorizations array 
	private function set_perms()
	{
		global $NagiosData;
		$permissions = $NagiosData->getProperty('permissions');
	
		foreach($permissions as $key => $array) {
			foreach($array as $user) {           //look for wildcard 
				if($user == $this->username || $user == '*') $this->authorize($key);
			}				
		}
	}
	//////////////////////////////////////////////////////
	//
	//activates authorization for user.  See authorizations.inc.php for auth list 
	//
	private function authorize($auth) //sets global permission 
	{
		global $authorizations; //global authorization array controller 
		$authorizations[$auth] = 1;
		$this->authKeys[$auth] = true; //class auth controller 
	}
	
	///////////////get methods 
	/**
	* @return mixed $authHosts array of all authorized hosts and services 
	*/ 
	public function get_authorized_hosts() {
		return $this->authHosts; 
	}
	
	/**
	*	@return string $username current user 
	*/ 	
	public function get_username() {
		return $this->username; 
	}	
	
	/**  
	*	@return boolean $admin boolean if user has admin privileges and can see and do everything 
	*/
	public function is_admin() {
		return $this->admin; 
	}
	/**
	*	@return boolean $key authorization key from cgi.cfg file 
	*/
	public function if_has_authKey($key) {
		if(isset($this->authKeys[$key]))
			return $this->authKeys[$key]; 
	}
	
	/**  
	*	@return boolean decide if this user is an admin 
	*/
	private function determine_admin() {
		if($this->username == 'nagiosadmin') return true; 
		foreach($this->authKeys as $key)
		{
			if($key != true) return false; //if all auth keys are set, user is an admin 
		}
		return true; 
		
	}
	
	 
	/**  
	*	sets global auths from cgi.cfg file 
	*	@TODO: move to protected method -> this will replace previous global auths in future versions
	*	@return null changes cgi.cfg booleans for current NagiosUser
	*/
	public function setAuthKey($keyname,$value) {
		if(isset($this->authKeys[$keyname])) {
			$this->authKeys[$keyname] = $value; 
		}	
	}
	
	/**
	*	tests if user can view host 
	*	@returns boolean
	*/  
	public function is_authorized_for_host($hostname) {
		//can user see everything? 
		if($this->admin == true || $this->sees_all == true) return true;  
		//user level filtering 
		if(isset($this->authHosts[$hostname]) && $this->authHosts[$hostname]['all_services']==true ) return true; 
		
		//not authorized 
		return false; 
	}
	
	/**
	*	tests if user can view service 
	*	@returns boolean
	*/  
	public function is_authorized_for_service($hostname,$service) {
		//can user see everything? 
		if($this->admin == true || $this->sees_all == true) return true;  
		//user level filtering 		
		if(isset($this->authHosts[$hostname]) && (in_array($service,$this->authHosts[$hostname]['services']) || $this->authHosts[$hostname]['all_services']==true) ) return true; 
		//not authorized 
		return false; 
	}
	
	
	/** ///////////////////////////////////////////////////
	*	main logic function for user-level filtering, builds $this->authHosts array  
	*	CREATES SINGLE MULTI-D HEIRARCHY ARRAY 
	*	LOGIC: - check for host contacts, and host contactgroups 
	*			 - check for host escalations, and hostescalation contactgroups 
	*			 - check for service contacts, and service contactgroups
	*			 - check for serviceescalation contacts, then serviceescalation contact groups 
	*
	* 	ARRAY STRUCTURE
	*	$authObjects = 
	*	array ( 'localhost' => array(
	*										'host_name' => 'localhost',
	*										'all_services' => true | false, 
	*										'services'	=> array( 0 => service1
	*																	 1 => service2
	*																	 3 => service3 )
	*
	*										) 
	*/
	private function build_authorized_objects() {
		global $NagiosData;
			
		//fetch necessary object config arrays 
		$hosts = $NagiosData->getProperty('hosts_objs');
		$contactgroups = $NagiosData->getProperty('contactgroups'); 
				
		//find relevant contact groups for user 
		foreach($contactgroups as $cg)
		{
			//echo $cg['contactgroup_name']; 
			if(strpos($cg['members'],$this->username)!==false) 
				$this->cg_memberships[] = $cg['contactgroup_name']; 	//add contactgroup to array if user is a member of it 		
		}
				
		///////////////////////////////////HOSTS////////////////////////
		foreach($hosts as $host)
		{
			//check is user is a direct contact 
			$key = $host['host_name']; 
			if(isset($host['contacts']) && strpos($host['contacts'],$this->username) !== false)
			{
				$this->authHosts[$key] = array('host_name' => $key, 'all_services' => true, 'services' => array()); 							
				continue; //skip to next host
			}	
			
			//if host has contact groups
			if(isset($host['contact_groups'])) 
			{
				$cgmems = explode(',',$host['contact_groups']); //members to array 
				foreach($cgmems as $cg)
				{
					if(in_array($cg,$this->cg_memberships)) //check if contact group is in user's list of memberships  
					{
						$this->authHosts[$key] = array('host_name' => $key, 'services' => array(), 'all_services' => true );   
						break; 
					}	//end IF
				
				}	//end FOREACH contactgroup member
			}//end IF contactgroups set 	
									
		}//end FOREACH host 
				
		/////////////////////////HOST ESCALATIONS///////////////////////
		//add hosts if user is assigned as a contact or contactgroup member  
		$this->add_escalated_hosts();  
		
		////////////////////////////SERVICES//////////////////////////
		//get services objects 		
		$services = $NagiosData->getProperty('services_objs');		
		//echo "Services: <br /><pre>".print_r($services,true)."</pre>"; 
		
		foreach($services as $service)
		{
			$key = $service['host_name']; 
			//check for authorized host first, if all services are authorized skip ahead 
			if(isset($this->authHosts[$key]) && $this->authHosts[$key]['all_services'] == true) continue; 
			
			//check for authorization at the service level 
			if(isset($service['contacts']) && (strpos($service['contacts'],$this->username) !== false)) //user is a contact 
			{
				//echo $service['service_description']." : ".$service['contacts'];  								
				//only add the service if it's not already there 
				if(!isset($this->authHosts[$key])) 										//if this is set somewhere else, the all_services boolean should already be set 
					$this->authHosts[$key] = array('host_name' => $key, 'services' =>array($service['service_description']), 'all_services' => false ); 												
				else 
				{				
					//only add service if it's not already there 
					if(!in_array($service['service_description'], $this->authHosts[$key]['services']) && $this->authHosts[$key]['all_services'] == false) 
						$this->authHosts[$key]['services'][] = $service['service_description']; 					
				}
				continue; 
			}
			
			//check against contactgroups 
			if(isset($service['contact_groups']) )
			{
				$cgmems = explode(',',$service['contact_groups']);
				foreach($cgmems as $cg)
				{
					if(in_array($cg,$this->cg_memberships)) //user is a contact for service 
					{						
						if(!isset($this->authHosts[$key])) 										//if this is set somewhere else, the all_services boolean should already be set 
							$this->authHosts[$key] = array('host_name' => $key, 'services' =>array(), 'all_services' => false ); 
						else
						{	//add service if it's not already in the array 
							if(!in_array($service['service_description'], $this->authHosts[$key]['services']) && $this->authHosts[$key]['all_services'] == false) 
								$this->authHosts[$key]['services'][] = $service['service_description'];							
						}						
						break; 
					}	//end IF		
				}	//end FOREACH contactgroup member			
			} //end IF contactgroups 			
		} //end services FOREACH 
	
		////////////////////////SERVICE ESCALATIONS/////////////////////
		//add services if user is assigned as an escalated contact or contactgroup member 
		$this->add_escalated_services(); 
		
	}//end function build_authorized_objects() 
	
		
	/**
	*	sweeps through host escalation definitions and adds to authHosts as needed 
	*/ 
	private function add_escalated_hosts() 
	{
		global $NagiosData;	
	
		$host_escs = $NagiosData->getProperty('hostescalations'); 
		foreach($host_escs as $he) //loop through all host escalations 
		{
			//check for authorized host first, skip ahead if it 
			if(isset($this->authHosts[$he['host_name']]) && $this->authHosts[$he['host_name']]['all_services']==false) continue; 
						
			//check if user is a contact for escalation 
			if(strpos($he['contacts'],$this->username) !==false) //if user is in list of contacts 
			{	//add host if not already there, or if it's there but not all services are authorized 
				if(!isset($this->authHosts[$he['host_name']]) || (isset($this->authHosts[$he['host_name']]) && $this->authHosts[$he['host_name']]['all_services']==false) ) //don't overwrite existing arrays 
					$this->authHosts[$he['host_name']] = array('host_name' => $he['host_name'], 'services' => array(), 'all_services' => true ); 
				//do nothing if host is already authorized 
				continue; //no need to check contactgroups 	
			}	
			//check if user's contactgroups are in the list
			if(isset($he['contact_groups']))
			{
				//compare arrays 
				$matches = array_intersect(explode(',',$he['contact_groups']),$this->cg_memberships); 
				if($matches !== false) // push host list into authHosts array  
				{
					if(!isset($this->authHosts[$he['host_name']]) || (isset($this->authHosts[$he['host_name']]) && $this->authHosts[$he['host_name']]['all_services']==false) ) //don't overwrite existing arrays 
						$this->authHosts[$he['host_name']] = array('host_name' => $he['host_name'], 'services' => array(), 'all_services' => true ); 
					//do nothing if host is already fully authorized 
				}	 				
			}//end IF contactgroup 
		}//end hostescalation loop 		
	}//end add_escalated_hosts() 	
	
	/**
	*	sweeps through escalation definitions and adds to $authHosts as needed 
	*	sort through all service escalations in objects.cache and push appropriate services onto array stack 
	*	NOTE host_name and service_descriptions are not comma delineated in objects.cache, all single definitions 
	*/ 
	private function add_escalated_services()
	{
		global $NagiosData;	
		//fetch escalations array 
		$serv_escs = $NagiosData->getProperty('serviceescalations'); 
		foreach($serv_escs as $se) //loop through all host escalations 
		{
			//skip ahead if all services are already authorized for host 
			if(isset($this->authHosts[$se['host_name']]) && $this->authHosts[$se['host_name']]['all_services'] == true) continue; 	
					
			//check if user is a contact for escalation 
			if(isset($se['contacts']) && strpos($se['contacts'],$this->username) !==false) //if user is in list of contacts 
			{			
				//check to see if host key exists in the array
				if(!isset($this->authHosts[$se['host_name']])) //don't overwrite existing arrays 					
					$this->authHosts[$se['host_name']] = array('host_name' => $se['host_name'], 'all_services'=> false, 'services' => array($se['service_description']) );  								 
				else //if it exists, push services onto array stack, services array should already be there  					
					$this->authHosts[$se['host_name']]['services'][] = $se['service_description'];																					

				continue; //no need to check contactgroups if defined as contact 	
			}	
			
			//check if user's contactgroups are in the list
			if(isset($se['contact_groups']))
			{
				
				//compare arrays 
				$matches = array_intersect(explode(',',$se['contact_groups']),$this->cg_memberships); 
				if($matches !== false) 
				{ 		//check to see if array key exists yet 
						if(!isset($this->authHosts[$se['host_name']]) ) //don't overwrite existing arrays 						
							$this->authHosts[$se['host_name']] = array('host_name' => $se['host_name'], 'services' => array($se['service_description']),'all_services'=>false );															 
						else //if it exists, push services onto array stack  																				
							$this->authHosts[$se['host_name']]['services'][] = $se['service_description'];	//object.cache separates services into individual defs 
				}			
			}//end IF contactgroups 
		}//end foreach service escalation 		
	}//end method add_escalated_services()  
	
} ///////////////////end NagiosUser class ////////////////////////



?>