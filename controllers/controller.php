<?php //controller.php		  access controls functions 


// Nagios V-Shell
// Copyright (c) 2010 Nagios Enterprises, LLC.
// Written by Mike Guthrie <mguthrie@nagios.com>
//
// LICENSE:
//
// This work is made available to you under the terms of Version 2 of
// the GNU General Public License. A copy of that license should have
// been provided with this software, but in any event can be obtained
// from http://www.fsf.org.
// 
// This work is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301 or visit their web page on the internet at
// http://www.fsf.org.
//
//
// CONTRIBUTION POLICY:
//
// (The following paragraph is not intended to limit the rights granted
// to you to modify and distribute this software under the terms of
// licenses that may apply to the software.)
//
// Contributions to this software are subject to your understanding and acceptance of
// the terms and conditions of the Nagios Contributor Agreement, which can be found 
// online at:
//
// http://www.nagios.com/legal/contributoragreement/
//
//
// DISCLAIMER:
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
// HOLDERS BE LIABLE FOR ANY CLAIM FOR DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
// GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, STRICT LIABILITY, TORT (INCLUDING 
// NEGLIGENCE OR OTHERWISE) OR OTHER ACTION, ARISING FROM, OUT OF OR IN CONNECTION 
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



function send_home() //redirects user to index page 
{
	header('Location: '.BASEURL);
}

// *OLD*
// view=<hosts,services,hostgroups,servicegroups>
// cmd=filter<hosts,services>,arg=<UP,DOWN,WARNING,UNREACHABLE,UNKNOWN>

// *NEW*
// mode=<view,filter,xml,json>
// type=<hosts,services,hostgroups,servicegroups>
// arg=<UP,DOWN,WARNING,UNREACHABLE,UNKNOWN,hostname>

// *IDEA*
// mode=<html,json,xml>
// type=<overview (default), hosts,services,hostgroups,servicegroups,hostdetail,servicedetail,object>
// * state_filter=UP,DOWN,WARNING,UNREACHABLE,UNKNOWN,critical
// * name_filter=<string>
// * objtype_filter=<string>

function page_router()
{

	global $authorizations;

	list($mode, $type) = array(NULL, NULL);
	list($state_filter, $name_filter, $objtype_filter) = array(NULL, NULL, NULL);

	if (isset($_GET['type'])) { $type = strtolower($_GET['type']); } else { $type = 'overview'; }
	if (isset($_GET['mode'])) { $mode = strtolower($_GET['mode']); } else { $mode = 'html'; }

	if (isset($_GET['state_filter'])   && trim($_GET['state_filter'])   != '') { $state_filter    = process_state_filter(htmlentities($_GET['state_filter']));     }
	if (isset($_GET['name_filter'])    && trim($_GET['name_filter'])    != '') { $name_filter     = process_name_filter(htmlentities($_GET['name_filter']),ENT_QUOTES);       }
	if (isset($_GET['objtype_filter']) && trim($_GET['objtype_filter']) != '') { $objtype_filter  = process_objtype_filter(htmlentities($_GET['objtype_filter'])); }

	list($data, $html_output_function) = array(NULL, NULL);

	switch($type) {
		case 'services':
		case 'hosts':
			if ($authorizations[$type] == 1) {
				$data = hosts_and_services_data($type, $state_filter, $name_filter);
				$html_output_function = 'hosts_and_services_output';
			}
		break;

		case 'hostgroups':
		case 'servicegroups':
			if($authorizations['hosts']==1)
			{ 
				if ($type == 'hostgroups' || ($type == 'servicegroups' && $authorizations['services']==1)) {
					$data = hostgroups_and_servicegroups_data($type, $name_filter);
					$html_output_function = 'hostgroups_and_servicegroups_output';
				}
			}	

		break;

		case 'hostdetail':
		case 'servicedetail':
			if($authorizations['hosts']==1 && $name_filter)
			{
				$data = host_and_service_detail_data($type, $name_filter);
				$html_output_function = 'host_and_service_detail_output';
			}
		break;

		case 'object':
			if ($objtype_filter)
			{
				if($authorizations['configuration_information']==1 || 
				   $authorizations['host_commands']==1             ||
				   $authorizations['service_commands']==1          ||
				   $authorizations['system_commands']==1)
				{
					$data = object_data($objtype_filter, $name_filter);
					$type = $objtype_filter;
					$html_output_function = 'object_output';
				}
			}	
		break;
		
		case 'backend':
		$xmlout = tac_xml(get_tac_data());
		break;

		case 'overview':
		default:
			//create function to return tac data as an array 
			$html_output_function = 'get_tac_html';
		break;
	}

	$output = NULL;
	switch($mode) {
		case 'html':
		default:
			$output =  mode_header($mode);
			$output .= $html_output_function($type, $data, $mode);
			$output .= mode_footer($mode);
		break;

		case 'json':
			header('Content-type: application/json');
			$output = json_encode($data);
		break;

		case 'xml':
		if($type!='backend')
		{
			require_once(DIRBASE.'/views/xml.php');
			$title = ucwords($type);
			build_xml_page($data, $title);		
			header('Location: '.BASEURL.'tmp/'.$title.'.xml');
		}
		header('Content-type: text/xml');
		if($type=='backend') echo $xmlout; //xml backend access for nagios fusion 
			#$output = build_xml_data($data, $title);
		break;
		case 'null':
		
		break; 
	}
	print $output;

}

function process_state_filter($filter_str)
{
	$ret_filter = NULL;
	$filter_str = strtoupper($filter_str);
	$valid_states = array('UP', 'DOWN', 'UNREACHABLE', 'OK', 'CRITICAL', 
								'WARNING', 'UNKNOWN', 'PENDING', 'PROBLEMS','UNHANDLED', 'ACKNOWLEDGED');


	if (in_array($filter_str, $valid_states))
	{
		$ret_filter = $filter_str;
	}
	return $ret_filter;
}

function process_name_filter($filter_str) {
	//$filter_str = preg_quote($filter_str, '/'); //removed strtolower -MG 
	$filter_str = strtolower(rawurldecode($filter_str)); 	
	return $filter_str;
}

function process_objtype_filter($filter_str)
{
	$ret_filter = NULL;
	$filter_str = strtolower($filter_str);
	$valid_objtypes = array('hosts_objs', 'services_objs', 'hostgroups_objs', 'servicegroups_objs',
		'timeperiods', 'contacts', 'contactgroups', 'commands');
	if (in_array($filter_str, $valid_objtypes))
	{
		$ret_filter = $filter_str;
	}
	return $ret_filter;
}


function mode_header($mode)
{
	$retval = '';
	switch($mode)
	{
		case 'html':
		default:
			$page_title = 'Nagios Visual Shell';
			include(DIRBASE.'/views/header.php');  //html head 
			$retval = display_header($page_title);
		break;
	}
	return $retval;
}

function mode_footer($mode)
{
	$retval = '';
	switch($mode)
	{
		case 'html':
		default:
			include(DIRBASE.'/views/footer.php');  //html head 
			$retval = display_footer();
		break;
	}
	return $retval;
}

function hosts_and_services_data($type, $state_filter=NULL, $name_filter=NULL)
{
	global $NagiosData;
	$data = $NagiosData->getProperty($type);
	$data_in = $data; 

	if ($state_filter)
	{
		if($state_filter == 'PROBLEMS' || $state_filter == 'UNHANDLED' || $state_filter == 'ACKNOWLEDGED')  //merge arrays for multiple states 
		{

			$data = array_merge(get_by_state('UNKNOWN', $data_in), get_by_state('CRITICAL', $data_in), 
										get_by_state('WARNING', $data_in), get_by_state('UNREACHABLE', $data_in),
										get_by_state('DOWN', $data_in));
			if($state_filter == 'UNHANDLED') //filter down problem array 
			{
				//loop and return array
				$unhandled = array(); 
				foreach($data as $d)
				{
					if($d['problem_has_been_acknowledged'] == 0 && $d['scheduled_downtime_depth'] == 0) $unhandled[] = $d; 
				} 
				$data = $unhandled; 
			}//end unhandled if 
			if($state_filter == 'ACKNOWLEDGED')
			{
				//loop and return array
				$acknowledged = array(); 
				foreach($data as $d)
				{
					if($d['problem_has_been_acknowledged'] > 0 || $d['scheduled_downtime_depth'] > 0) $acknowledged[] = $d; 
				} 
				$data = $acknowledged; 				
			}//end acknowledged if 
		}
		else 
		{
			$data = get_by_state($state_filter, $data); 
		}
	}
	if ($name_filter)
	{
		$name_data = get_by_name($name_filter, $data);
		$service_data = get_by_name($name_filter, $data, 'service_description');
		$data = $name_data;
		foreach ($service_data as $i => $service)
		{
			if (!isset($data[$i])) { $data[$i] = $service; }
		}
	}
	//var_dump($data); 
	return $data;
}

function hosts_and_services_output($type, $data, $mode)
{
	$retval = '';
	switch($mode)
	{
		case 'html':
			list($start, $limit) = get_pagination_values();
			$title = ucwords(preg_replace('/objs/', 'Objects', preg_replace('/_/', ' ', $type)));
			include_once(DIRBASE.'/views/'.$type.'.php');
			$display_function = 'display_'.$type;
			$retval = $display_function($data, $start, $limit);
		break;
	}
	return $retval;
}

function hostgroups_and_servicegroups_data($type, $name_filter=NULL)
{
	include_once(DIRBASE.'/views/'.$type.'.php');
	$data_function = 'get_'.preg_replace('/s$/', '', $type).'_data';
	$data = $data_function();
	if ($name_filter)
	{

		// TODO filters against Services and/or hosts within groups, status of services/hosts in groups, etc...
		$name = preg_quote($name_filter, '/');
		$match_keys = array_filter(array_keys($data), create_function('$d', 'return !preg_match("/'.$name.'/i", $d);'));
		// XXX is there a better way?
		foreach ($match_keys as $key)
		{
			unset($data[$key]);
		}
	}
	return $data;
}

function hostgroups_and_servicegroups_output($type, $data, $mode)
{
	$retval = '';
	switch($mode)
	{
		case 'html':
			$title = ucwords(preg_replace('/objs/', 'Objects', preg_replace('/_/', ' ', $type)));
			$display_function = 'display_'.$type;
			$retval = $display_function($data);
		break;
	}
	return $retval;
}

function host_and_service_detail_data($type, $name)
{
	$data_function = 'process_'.preg_replace('/detail/', '_detail', $type);
	$data = $data_function(stripslashes($name)); //added stripslashes because hostnames with periods had them in the variable -MG 
	return $data;
}

function host_and_service_detail_output($type, $data, $mode)
{
	$retval = '';
	switch($mode)
	{
		case 'html':
			require_once(DIRBASE.'/views/'.$type.'s.php');
			$display_function = 'get_'.preg_replace('/detail/', '_detail', $type).'s'; 
			$retval = $display_function($data);
		break;
	}
	return $retval;
}

function object_data($objtype_filter, $name_filter)
{
	$valid_objtype_filters = array('hosts_objs', 'services_objs', 'hostgroups_objs', 'servicegroups_objs',
		'timeperiods', 'contacts', 'contactgroups', 'commands');

	if (in_array($objtype_filter, $valid_objtype_filters)) {
		global $NagiosData;
		$data = $NagiosData->getProperty($objtype_filter);

		if ($name_filter)
		{
			$name_data = get_by_name($name_filter, $data);
			$service_data = get_by_name($name_filter, $data, 'service_description');

			$data = $name_data;
			foreach ($service_data as $i => $service)
			{
				if (!isset($data[$i])) { $data[$i] = $service; }
			}
		}
	}
	return $data;
}

function object_output($objtype_filter, $data, $mode)
{
	$retval = '';
	switch($mode)
	{
		case 'html':
			include(DIRBASE.'/views/config_viewer.php');
			$retval = build_object_list($data, $objtype_filter);
		break;
	}
	return $retval;
}


function get_pagination_values()
{
	$start = isset($_GET['start']) ? htmlentities($_GET['start']) : 0;
	$limit = isset($_COOKIE['limit']) ? $_COOKIE['limit'] : RESULTLIMIT;
	if(isset($_POST['pagelimit']))
	{       
		//set a site-wide cookie for the display limit 
		setcookie('limit', $_POST['pagelimit']);
		$limit = $_POST['pagelimit'];
	}

	return array($start, $limit);
}

////////////////////////////////////////////////////////////
//$username is obtained from $_SERVER authorized user for nagios 
//
function set_perms($username)
{
	global $NagiosData;
	$permissions = $NagiosData->getProperty('permissions');

	foreach($permissions as $key => $array)//perms  = array('system_information'
	{
		foreach($array as $user)
		{
			if($user == $username || $user == '*') 
			{
				//print "authorizing $username";
				authorize($key);
			}
		}				
	}
}
//////////////////////////////////////////////////////
//
//activates authorization for user.  See authorizations.inc.php for auth list 
//
function authorize($auth) //sets global permission 
{
	global $authorizations; //global authorization array controller 
	$authorizations[$auth] = 1;
}

?>
