<?php
/*
 * Microsoft Azure IoT Hub Library for PHP
 * 
 *  MIT License
 * 
 * Copyright (c) 2017 Peter Postmann (peter@postmann.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Azure_IoT_SDK;

require_once 'HTTP/Request2.php';

class Result
{
    public $status;
    public $header;
    public $body;
    public $data;
    public $app_error;
    public $json_error;
    
    public function __construct(int $status, array $header, string $body, $data, bool $app_error, int $json_error)
    {
        $this->status     = $status;
        $this->header     = $header;
        $this->body       = $body;
        $this->data       = $data;
        $this->app_error  = $app_error;
        $this->json_error = $json_error;
    }
}

class Response
{
    public $status; // success, fail, error
    public $data;
    public $message;
    public $code;
    
    public function __construct(string $status, $data, string $message = '', int $code = 0)
    {
        $this->status  = $status;
        $this->data    = $data;
        $this->message = $message;
        $this->code    = $code;
    }
}

class IotHub
{
  private $host;
  private $master_key;
  private $error_handler  = ['Azure_IoT_SDK\IotHub','defaultErrorHandler'];
  private $request_charge = 0;
  private $policyName;
  
  public static $api_version = '2016-02-03';

   /**
     * __construct
     *
     * @access public
     * @param string   $host            URI of Key
     * @param string   $master_key      Primary or Secondary key
     * @param array    $options         Configuration
     *        callable  error_handler   Function to handle errors
     *        bool      enableCache     Enable result caching
     */
    public function __construct(string $host, string $master_key, string $policyName='iothubowner', array $options=array())
    {
        $this->host          = $host;
        $this->master_key    = $master_key;
        $this->policyName    = $policyName;

        $available_options = array('error_handler');
        foreach ($available_options as $name) {
            if (isset($options[$name])) {
                $this->$name = $options[$name];
            }
        }
    }

    public static function generateSasToken(string $uri, string $signingKey, string $policyName, int $expiresIn) 
    {
        $resourceUri = urlencode($uri);

        // Set expiration in seconds
        $expires = ceil(time() + $expiresIn);
        $toSign  = $resourceUri."\n".$expires;
    
        // Use crypto
        $key = base64_decode($signingKey);
        $sig = urlencode(base64_encode(hash_hmac('sha256', $toSign, $key, true)));
        
        // Construct autorization string
        return  'SharedAccessSignature sr='.$resourceUri.
                '&sig='.$sig.
                '&se='.$expires.
                ((!empty($policyName)) ? '&skn='.$policyName : '');
    }
 
    /**
     * getHeaders
     *
     * @link https://docs.microsoft.com/de-at/rest/api/
     * @access private
     * @param string $endpoint      Request endpoint
     * @param int    $contentLength Body size
     * @return string Array of Request Headers
     */
    private function getHeaders(string $endpoint, int $contentLength)
    {
        $token = static::generateSasToken($endpoint, $this->master_key, $this->policyName, 120);

        return Array(
            'Accept: application/json',
            'Host: '.$this->host,
            'Content-Length: '.$contentLength,
            'User-Agent: azure-iot-hub.php.sdk/1.0.0',
           // 'Cache-Control: no-cache',
            'Authorization: ' . $token
        );
  }

  /**
   * request
   *
   * use cURL functions
   *
   * @access private
   * @param string $path    request path
   * @param string $method  request method
   * @param array  $headers request headers
   * @param string $body    request body (JSON or QUERY)
   * @param array  $params  query params
   * @return Result Result Object
   */
    private function request(string $path, string $method, array $headers=array(), string $body = NULL, array $params = array())
    {
        $enpoint = $this->host.$path;
        
        $requestHeaders = $this->getHeaders($enpoint, strlen($body));
        $requestHeaders = array_merge($requestHeaders, $headers);

        $queryString = '?api-version='.self::$api_version;
        foreach($params as $param => $value) $queryString = $queryString.'&'.$param.'='.$value;

        $request = new \Http_Request2('https://'.$enpoint.$queryString);

        var_dump($requestHeaders);

        $request->setHeader($requestHeaders);

        if ($method === "GET") {
            $request->setMethod(\HTTP_Request2::METHOD_GET);
        } else if ($method === "POST") {
            $request->setMethod(\HTTP_Request2::METHOD_POST);
        } else if ($method === "PUT") {
            $request->setMethod(\HTTP_Request2::METHOD_PUT);
        } else if ($method === "DELETE") {
            $request->setMethod(\HTTP_Request2::METHOD_DELETE);
        }
        
        if ($body) {
            $request->setBody($body);
        }
        
        $error = false;
        
        try
        {
            $http_response = $request->send();  

            $body       = $http_response->getBody();
            $data       = !empty($body) ? json_decode($body, true) : null;
            $json_error = !empty($body) ? json_last_error()        : JSON_ERROR_NONE;
            
            $result   = new Result(
                                $http_response->getStatus(), 
                                $http_response->getHeader(), 
                                $body,
                                $data,
                                $this->checkForErrors(debug_backtrace()[1]['function'], $http_response->getStatus()),
                                $json_error
                            );
                            
            $this->request_charge += ($http_response->getHeader('x-ms-request-charge') ? $http_response->getHeader('x-ms-request-charge') : 0);
                            
            $response = new Response('success', $result);
        }
        catch (HttpException $ex)
        {
            $result   = null;
            $response = new Response('error', $ex, $ex->getMessage(), $ex->getCode());
        }

        if($response->status != 'success' || $response->data->app_error || $response->data->json_error)
            $result = $this->callErrorHandler($response, $result);

        return $result;
    }

    /**
     * defaultErrorHandler
     *
     * @access public
     * @param object $response Response Data
     * @return object Modified response Data
     */
    public static function defaultErrorHandler($response)
    {
        if($response->status == 'error')        throw $response->data;
        else if($response->data->json_error)    throw new \Exception(json_last_error_msg(), $response->data->json_error);
        else if($response->data->app_error)     throw new \Exception('Unexpected response code', $response->data->status);
        else                                    throw new \Exception('Unexpected error');

        return $response;
    }

    /**
     * callErrorHandler
     *
     * @access public
     * @param varargs $params  Arguments to pass to the error handler
     * @return object Modified response Data
     */
    public function callErrorHandler(...$params)
    {
        return call_user_func_array($this->error_handler, $params);
    }

    /**
     * checkForErrors
    *
    * @access private
    * @param string $action   Action executed
    * @param string $response Response
    * @return bool error
    */
    private function checkForErrors(string $action, int $http_status_code)
    {
        $error = false;

             if (0 === strpos($action, 'query'))           $error = ($http_status_code != 204);
        else if (0 === strpos($action, 'abandon'))         $error = ($http_status_code != 204); 
        else if (0 === strpos($action, 'complete'))        $error = ($http_status_code != 204); 
        else if (0 === strpos($action, 'bulk'))            $error = ($http_status_code != 200); 
        else if (0 === strpos($action, 'invoke'))          $error = ($http_status_code != 200); 
        else if (0 === strpos($action, 'create'))          $error = ($http_status_code != 200); 
        else if (0 === strpos($action, 'receive'))         $error = ($http_status_code != 200 && $http_status_code != 204);
        else if (0 === strpos($action, 'get'))             $error = ($http_status_code != 204 && $http_status_code != 404);
        else if (0 === strpos($action, 'put'))             $error = ($http_status_code != 200 && $http_status_code != 403); 
        else if (0 === strpos($action, 'purge'))           $error = ($http_status_code != 200 && $http_status_code != 404);
        else if (0 === strpos($action, 'delete'))          $error = ($http_status_code != 204 && $http_status_code != 404                                       
                                                                                              && $http_status_code != 412); 


        else if (0 === strpos($action, 'get'))             $error = ($http_status_code != 200 && $http_status_code != 304                                       
                                                                                              && $http_status_code != 404); 
        else if (0 === strpos($action, 'create'))          $error = ($http_status_code != 201 && $http_status_code != 409);
        else if (0 === strpos($action, 'replace'))         $error = ($http_status_code != 200 && $http_status_code != 404                                       
                                                                                              && $http_status_code != 409                                       
                                                                                              && $http_status_code != 412);
        else if (0 === strpos($action, 'delete'))          $error = ($http_status_code != 204 && $http_status_code != 404                                       
                                                                                              && $http_status_code != 412); 
        else if (0 === strpos($action, 'execute'))         $error = ($http_status_code != 200);
        else                                               $error = ($http_status_code < 200  || $http_status_code  > 409);

        return $error;
    }

    /**
     * bulkDeviceOperation
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/deviceapi/bulkdeviceoperation
     * @access public
     * @param json Devices
     * @return Result Result Object
     */
    public function bulkDeviceOperation(string $devices)
    {
        return $this->request('/devices', 'POST', array(), $devices);
    }

    /**
     * deleteDatabase
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/deviceapi/deletedevice
     * @access public
     * @param string deviceId        Device ID
     * @param string if_match_etag   Resource is updated if server ETag value matches request ETag value, else operation is rejected with "HTTP 412 Precondition failure"
     * @return string JSON response
     */
    public function deleteDevice(string $deviceId, string $if_match_etag='*')
    {
        $headers = array('If-Match:'.$if_match_etag);
        return $this->request('/devices/'.$deviceId, 'DELETE', $headers);
        
    }

    /**
     * getDevice
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/deviceapi/getdevice
     * @access public
     * @param string deviceId        Device ID
     * @return Result Result Object
     */
    public function getDevice(string $deviceId)
    {    
        return $this->request('/devices/'.$deviceId, 'GET', $headers);
    }

    /**
     * getDevices
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/DeviceApi/GetDevices
     * @access public
     * @param int top Maximum number of devices that are returned (range 1-1000)
     * @return Result Result Object
     */
    public function getDevices(int $top=0)
    {
        $queryParams = array();
        if($top != 0) $queryParams['top'] = $top;

        return $this->request('/devices', 'GET', array(), '', $queryParams);
    }
    
    /**
     * getRegistryStatistics
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/deviceapi/getregistrystatistics
     * @access public
     * @return Result Result Object
     */
    public function getRegistryStatistics()
    {
        return $this->request('/statistics/devices', 'GET');
    }
    
    /**
     * getServiceStatistics
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/deviceapi/getservicestatistics
     * @access public
     * @return Result Result Object
     */
    public function getServiceStatistics(int $top=0)
    {
        return $this->request('/statistics/service', 'GET');
    }
    
    /**
     * purgeCommandQueue
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/deviceapi/getservicestatistics
     * @access public
     * @return Result Result Object
     */
    public function purgeCommandQueue(string $deviceId)
    {
        return $this->request('/devices/'.$deviceId.'/commands', 'DELETE');
    }

    /**
     * putDevice
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/deviceapi/purgecommandqueue
     * @access public
     * @param string $rid_id Resource ID
     * @param string $json   JSON request
     * @return string JSON response
     */
    public function putDevice(string $deviceId, string $device)
    {
        return $this->request('/devices/'.$deviceId, 'PUT', array(), $device);
    }
    
    /**
     * queryDevices
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/deviceapi/querydevices
     * @access public
     * @param string $rid_id Resource ID
     * @param string $json   JSON request
     * @return string JSON response
     */
    public function queryDevices(string $query)
    {
        return $this->request('/devices/query/', 'POST ', array(), $query);
    }
    
    /**
     * getDeviceTwin
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/devicetwinapi/getdevicetwin
     * @access public
     * @param string deviceId        Device ID
     * @return Result Result Object
     */
    public function getDeviceTwin(string $deviceId)
    {    
        return $this->request('/twins/'.$deviceId, 'GET');
    }
    
    /**
     * invokeDeviceMethod
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/devicetwinapi/invokedevicemethod
     * @access public
     * @param string deviceId        Device ID
     * @return Result Result Object
     */
    public function invokeDeviceMethod(string $deviceId, string $methodName, string $payload, int $connectTimeoutInSeconds=30, int $responseTimeoutInSeconds=30)
    {    
        $body = '{"methodName":"'.$methodName.'","responseTimeoutInSeconds":'.$responseTimeoutInSeconds.',"connectTimeoutInSeconds":'.$connectTimeoutInSeconds.',"payload":'.$payload.'}';

        return $this->request('/twins/'.$deviceId.'/methods', 'POST', array(), $body);
    }
    
    /**
     * updateDeviceTwin
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/devicetwinapi/updatedevicetwin
     * @access public
     * @param string $deviceId        Device ID
     * @param string $data            Device ID
     * @return Result Result Object
     */
    public function updateDeviceTwin(string $deviceId, string $data)
    {    
        $body = '{"methodName":"'.$methodName.'","responseTimeoutInSeconds":'.$responseTimeoutInSeconds.',"connectTimeoutInSeconds":'.$connectTimeoutInSeconds.',"payload":'.$payload.'}';

        return $this->request('/twins/'.$deviceId.'/methods', 'POST', array(), $body);
    }

    /**
     * abandonDeviceBoundNotification
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/httpruntime/abandondeviceboundnotification
     * @access public
     * @param string $deviceId        Device ID
     * @param string $etag            Device ETAG
     * @return Result Result Object
     */
    public function abandonDeviceBoundNotification(string $deviceId, string $etag)
    {    
        return $this->request('/devices/'.$deviceId.'/messages/deviceBound/'.$etag.'/abandon', 'POST');
    }

    /**
     * completeDeviceBoundNotification
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/httpruntime/completedeviceboundnotification
     * @access public
     * @param string $deviceId        Device ID
     * @param string $etag            Device ETAG
     * @param string $reject          A rejected message causes a  message to be deadlettered
     * @return Result Result Object
     */
    public function completeDeviceBoundNotification(string $deviceId, string $etag, string $reject=null)
    {    
        $queryParams = array();
        if($reject !== null) $queryParams['reject'] = $reject;

        return $this->request('/devices/'.$deviceId.'/messages/deviceBound/'.$etag, 'DELETE', array(), '', $queryParams);
    }

    /**
     * createFileUploadSasUri
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/httpruntime/createfileuploadsasuri
     * @access public
     * @param string deviceId        Device ID
     * @param string blobName        Name of the file for which a SAS URI will be generated
     * @return Result Result Object
     */
    public function createFileUploadSasUri(string $deviceId, string $blobName)
    {    
        $body = '{"blobName": "'.$blobName.'"}';

        return $this->request('/devices/'.$deviceId.'/files', 'POST', array(), $body);
    }

    /**
     * receiveDeviceBoundNotification
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/httpruntime/receivedeviceboundnotification
     * @access public
     * @param string deviceId        Device ID
     * @return Result Result Object
     */
    public function receiveDeviceBoundNotification(string $deviceId)
    {    
        return $this->request('/devices/'.$deviceId.'/messages/deviceBound', 'GET');
    }

    /**
     * sendDeviceEvent
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/httpruntime/senddeviceevent
     * @access public
     * @param string deviceId        Device ID
     * @param string data            
     * @return Result Result Object
     */
    public function sendDeviceEvent(string $deviceId, string $data)
    {    
        return $this->request('/devices/'.$deviceId.'/messages/events', 'POST', array(), $data);
    }

    /**
     * updateFileUploadStatus
     *
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/httpruntime/updatefileuploadstatus
     * @access public
     * @param string $deviceId          Device ID
     * @param string $correlationId     Id which was returned by createFileUploadSasUri
     * @param bool   $isSuccess         
     * @param int    $statusCode 
     * @param string $statusDescription
     * @return Result Result Object
     */
    public function updateFileUploadStatus(string $deviceId, string $correlationId, bool $isSuccess, int $statusCode, string $statusDescription)
    {    
        return $this->request('/devices/'.$deviceId.'/files/notifications', 'POST', array(), $data);
    }

    /**
     * checkIotHubNameAvailability
     *
     * Check if an IoT hub name is available
     * 
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/iothubresource/checknameavailability
     * @access public
     * @param string $subscriptionId    Subscription  ID
     * @param string $name              The name of the IoT hub to check
     * @return Result Result Object
     */
    public function checkIotHubNameAvailability(string $subscriptionId, string $name)
    {    
        return $this->request('/subscriptions/'.$subscriptionId.'/providers/Microsoft.Devices/checkNameAvailability', 'POST');
    }

    /**
     * createEventHubConsumerGroup
     *
     * Add a consumer group to an Event Hub-compatible endpoint in an IoT hub
     * 
     * @link https://docs.microsoft.com/en-us/rest/api/iothub/iothubresource/createeventhubconsumergroup
     * @access public
     * @param string $subscriptionId	        The subscription identifier.
     * @param string $resourceGroupName	        The name of the resource group that contains the IoT hub.
     * @param string $resourceName	            The name of the IoT hub.
     * @param string $eventHubEndpointName	    The name of the Event Hub-compatible endpoint in the IoT hub.
     * @param string $name                      The name of the consumer group to add.
     * @return Result Result Object
     */
    public function createEventHubConsumerGroup(string $subscriptionId, string $resourceGroupName, string $resourceName, string $eventHubEndpointName, string $name)
    {
        return $this->request('subscriptions/'.$subscriptionId.'/resourceGroups/'.$resourceGroupName.'/providers/Microsoft.Devices/IotHubs/'.
                                               $resourceName.'/eventHubEndpoints/'.$eventHubEndpointName.'/ConsumerGroups/'.$name, 'PUT ');
    }
}

?>
    