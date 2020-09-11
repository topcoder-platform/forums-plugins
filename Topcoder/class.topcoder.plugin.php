<?php
/**
 * Class TopcoderPlugin
 */

if (!class_exists('Auth0\SDK\Auth0')){
    require __DIR__ . '/vendor/autoload.php';
}

use Garden\Schema\Schema;
use Garden\Web\Data;
use Garden\Web\Exception\NotFoundException;
use Vanilla\ApiUtils;


use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Helpers\JWKFetcher;
use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\TokenVerifier;
use Auth0\SDK\Helpers\Tokens\SymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\IdTokenVerifier;
use Auth0\SDK\JWTVerifier;
use Kodus\Cache\FileCache;
use Auth0\SDK\Auth0;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;




class TopcoderPlugin extends Gdn_Plugin {

    private $jwksFetcher;

    /**
     * Extra styling on the discussion view.
     *
     * @param \Vanilla\Web\Asset\LegacyAssetModel $sender
     */
    public function assetModel_styleCss_handler($sender) {
        $sender->addCssFile('topcoder.css', 'plugins/Topcoder');
    }

    /**
     * Check if we have a valid token associated with the request.
     */
    public function gdn_auth_startAuthenticator_handler() {
       $this->log('TopcoderPlugin: gdn_auth_startAuthenticator_handler', []);
       $cookiesToken =  $_COOKIE['auth0Jwt'];
       $headersToken = $this->getBearerToken();
       $accessToken = $headersToken ? $headersToken : $cookiesToken;

       if($cookiesToken) {
           $this->log('Token from Cookies', ['value' => $cookiesToken]);
       }
       if($headersToken) {
           $this->log('Token from Headers', ['value' => '' . $headersToken]);
       }

       if($accessToken) {
           $this->log('Using Token', ['value' => $accessToken]);
       } else {
           $this->log('Token wasn\'t found', []);
       }

       $useTopcoderAuthToken = c('Plugins.Topcoder.UseTopcoderAuthToken');
       if($useTopcoderAuthToken && $accessToken) {
            // If a token found to end the existing session
            if(Gdn::session()->isValid()) {
                try {
                    Gdn::session()->end(Gdn::authenticator());
                } catch  (\Exception $e) {
                    $this->log('Ending session', ['Error' => $e.getMessage]);
                    return;
                }
            }
            $AUTH0_DOMAIN = 'https://topcoder-dev.auth0.com/';
            $AUTH0_AUDIENCE = getenv('AUTH0_CLIENT_ID');
            $CLIENT_SECRET = getenv('AUTH0_CLIENT_SECRET');

            $decodedToken = (new Parser())->parse((string) $accessToken);
            $this->log('Decoded Token', ['Headers' => $decodedToken->getHeaders(), 'Claims' => $decodedToken->getClaims()]);
            $signatureVerifier = null;
            $issuer = $decodedToken->getClaim('iss');
            if ($issuer != $AUTH0_DOMAIN){
               $this->log('Invalid token issuer', ['Found issuer' => $issuer, 'Expected issuer' => $AUTH0_DOMAIN]);
               return;
            }
            if($decodedToken->getHeader('alg') === 'RS256' ) {
                $jwksUri  = $issuer . '.well-known/jwks.json';
                if($this->jwksFetcher == null) {
                     $this->jwksFetcher = new JWKFetcher();
                 }
                $jwks = $this->jwksFetcher->getKeys($jwksUri);
                $signatureVerifier= new AsymmetricVerifier($jwks);
            } else if ($decodedToken->getHeader('alg') === 'HS256' ) {
                $signatureVerifier = new SymmetricVerifier($CLIENT_SECRET);
            } else {
                return;
            }

            $tokenVerifier = new IdTokenVerifier(
                $issuer,
                $AUTH0_AUDIENCE,
                $signatureVerifier
            );

            try {
                $tokenVerifier->verify($accessToken);
                $this->log('Verification of the token was successful', ['result' ,true]);
            } catch (\Exception $e) {
                $this->log('Verification of the token was failed', ['result' => $e.getMessage]);
                return;
            }

            $topcoderUserName = $decodedToken->getClaim('nickname');
            if($topcoderUserName) {
                $this->log('Trying to signIn ...', ['username' => $topcoderUserName]);

                $userModel = Gdn::userModel();
                $user = $userModel->getByUsername($topcoderUserName);
                if($user) {
                    $userID = val('UserID', $user);
                    $this->log('Found Vanilla User:', ['Vanilla UserID' => $userID]);
                    if($userID) {
                        // Start the 'session'
                        if (!Gdn::session()->isValid()) {
                            Gdn::session()->start($userID, false);
                        }
                    }
                } else {
                    $this->log('Vanilla User was not found', []);
                }
            }
        }
    }

    public function log($message, $data) {
        if (c('Vanilla.SSO.Debug')) {
            Logger::event(
                'sso_logging',
                Logger::INFO,
                $message,
                $data
            );
        }
    }

    /**
     * Get Authorization headers
     * @return string|null
     */
    function getAuthorizationHeader() {
        $headers = null;

        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        }
        else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            //print_r($requestHeaders);
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        return $headers;
    }

    /**
     * Get Bearer Token from the heders
     * @return mixed|null
     */
    function getBearerToken() {
        $headers = $this->getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }

      /**
     * The settings page for the topcoder plugin.
     *
     * @param Gdn_Controller $sender
     */
    public function settingsController_topcoder_create($sender) {
        $sender->permission('Garden.Settings.Manage');
        $cf = new ConfigurationModule($sender);
        $cf->initialize([
            'Plugins.Topcoder.BaseApiURL' => ['Control' => 'TextBox', 'Default' => 'https://api.topcoder-dev.com', 'Description' => 'TopCoder Base API URL'],
            'Plugins.Topcoder.MemberApiURI' => ['Control' => 'TextBox', 'Default' => '/v3/members', 'Description' => 'Topcoder Member API URI'],
            'Plugins.Topcoder.RoleApiURI' => ['Control' => 'TextBox', 'Default' => '/v3/roles', 'Description' => 'Topcoder Role API URI'],
            'Plugins.Topcoder.MemberProfileURL' => ['Control' => 'TextBox', 'Default' => 'https://www.topcoder.com/members', 'Description' => 'Topcoder Member Profile URL'],
            'Plugins.Topcoder.UseTopcoderAuthToken' => ['Control' => 'CheckBox', 'Default' => false, 'Description' => 'Use Topcoder access token to log in to Vanilla'],
        ]);

        $sender->setData('Title', sprintf(t('%s Settings'), 'Topcoder'));
        saveToConfig('Conversations.Moderation.Allow', true);
        $cf->renderAll();
    }

    /**
     * Add the button to generate GDPR report
     * @param $sender
     * @param $args
     */
    public function userController_UserCell_handler($sender, $args) {
        ?>
        <td>
            <?php
                echo !$args['User']->UserID? '' :'<a class="btn btn-icon-border" href="' . url('/user/export/' . $args['User']->UserID) . '">Export</a>';
             ?>
        </td>
        <?php
      }

    /**
     * Generate  an export report (/user/export/{:userID})
     *
     * @param $sender
     * @param $args
     * @throws Gdn_UserException
     */
    public function userController_export_create($sender, $args) {
        $userID = $args[0];

        if (Gdn::request()->isAuthenticatedPostBack()) {
            throw new Exception('Requires GET', 405);
        }

        $userModel = new UserModel();
        $user = $userModel->getID($userID, DATASET_TYPE_ARRAY);
        if (!$user) {
            throw notFoundException('User');
        }

        //Max limit for all API controllers;
        $MAX_LIMIT = 100;

        //$dateInserted = '';
        //$dateUpdated = '';

        $user = self::getData(UsersApiController::class, array('id' => $userID));
        $discussions = TopcoderPlugin::getPagedData(DiscussionsApiController::class, array('page' => 1, 'limit' =>  $MAX_LIMIT, 'insertUserID'=> $userID));
        $comments = TopcoderPlugin::getPagedData(CommentsApiController::class, array('page' => 1, 'limit' =>  $MAX_LIMIT, 'insertUserID'=> $userID));
        $messages = TopcoderPlugin::getPagedData(MessagesApiController::class, array('page' => 1, 'limit' =>  $MAX_LIMIT, 'insertUserID'=> $userID));
        $conversations = TopcoderPlugin::getPagedData(ConversationsApiController::class, array('page' => 1, 'limit' =>  $MAX_LIMIT, 'insertUserID'=> $userID, 'participantUserID' => $userID));
        $drafts = TopcoderPlugin::getPagedData(DraftsApiController::class, array('page' => 1, 'limit' =>  $MAX_LIMIT, 'insertUserID'=> $userID));

        $reportData =new StdClass();
        $reportData->user = $user;
        $reportData->discussions = $discussions;
        $reportData->comments = $comments;
        $reportData->conversations = $conversations;
        $reportData->messages = $messages;
        $reportData->drafts = $drafts;
        $reportData->ips = $userModel->getIPs($userID);

        $result = json_encode($reportData, JSON_PRETTY_PRINT);
        header('Content-Disposition: attachment; filename="user-'.$userID.'.json"');
        header('Content-Type: application/json');
        header('Content-Length: ' . strlen($result));
        header('Connection: close');
        echo $result;

    }

    private static function getData($class, $query) {
        if($class === DiscussionsApiController::class) {
            $apiControler = Gdn::getContainer()->get(DiscussionsApiController::class);
            return $apiControler->index($query);
        } else if($class === UsersApiController::class) {
            $apiController = Gdn::getContainer()->get(UsersApiController::class);
            return $apiController->get($query['id'], array());
        } else if($class === CommentsApiController::class) {
            $apiControler = Gdn::getContainer()->get(CommentsApiController::class);
            return $apiControler->index($query);
        } else if($class === MessagesApiController::class) {
            $apiControler = Gdn::getContainer()->get(MessagesApiController::class);
            return $apiControler->index($query);
        } else if($class === ConversationsApiController::class) {
            $apiControler = Gdn::getContainer()->get(ConversationsApiController::class);
            return $apiControler->index($query);
        }  else if($class === DraftsApiController::class) {
            return self::getDrafts(DraftsApiController::class,$query);
        }  else {
            throw new Exception('API Controller not supported');
        }
    }

    /**
     * Get data from REST API without auth tokens
     * There are two types of paging meta data
     *  1.  { "page": 1,
     *        "pageCount": 7,
     *        "urlFormat": "\/api\/v2\/discussions?page=%s&limit=1",
     *        "totalCount": 7
     *  }
     * 2. {
     *     "page" : 1,
     *     "more" : 1,
     *     "urlFormat": /api/v2/discussions?page=%s&amp;limit=1&amp;insertUserID=2,
     *  }
     * @param $class
     * @param $query
     * @return array
     */
    private static function getPagedData($class, $query) {
        $result = self::getData($class, $query);
        $records = $result->getData();
        $meta = $result->getMeta('paging');
        if(array_key_exists('totalCount', $meta)) {
            $records = $result->getData();
            // Load from the next page
            for ($i = 2; $i < $meta['totalCount']; $i++) {
                $query['page'] = $i;
                $nextPageData = self::getData($class, $query);
                $records = array_merge($records, $nextPageData->getData());
            }
        } else {
            $currentPage = 2;
            $hasNextPage = $meta['more'];
            while($hasNextPage === true) {
                $query['page'] = $currentPage;
                $nextPageData = self::getData($class, $query);
                $meta = $nextPageData->getMeta('paging');
                $hasNextPage =  $meta['more'];
                $records = array_merge($records, $nextPageData->getData());
                $currentPage++;
            }
        }
        return $records;
    }

    /**
     * List drafts created by the user.
     *
     * @param array $query The query string.
     * @return Data
     */
    private static function getDrafts($class, array $query) {
        $apiControler = Gdn::getContainer()->get($class);
        $in = $apiControler->schema([
            'insertUserID:i?' => [
                'description' => 'Author',
                'default' => 1,
                'minimum' => 1
            ],
            'page:i?' => [
                'description' => 'Page number.',
                'default' => 1,
                'minimum' => 1
            ],
            'limit:i?' => [
                'description' => 'Desired number of items per page.',
                'default' => 30,
                'minimum' => 1,
                'maximum' => 100
            ]
        ], 'in')->setDescription('List drafts created by the user.');
        $out = $apiControler->schema([':a' => Schema::parse([
            'draftID:i' => 'The unique ID of the draft.',
            'recordType:s' => [
                'description' => 'The type of record associated with this draft.',
                'enum' => ['comment', 'discussion']
            ],
            'parentRecordID:i|n' => 'The unique ID of the intended parent to this record.',
            'attributes:o' => 'A free-form object containing all custom data for this draft.',
            'insertUserID:i' => 'The unique ID of the user who created this draft.',
            'dateInserted:dt' => 'When the draft was created.',
            'updateUserID:i|n' => 'The unique ID of the user who updated this draft.',
            'dateUpdated:dt|n' => 'When the draft was updated.'
        ])], 'out');
        $query = $in->validate($query);
        $where = ['InsertUserID' => $query['insertUserID']];
        list($offset, $limit) = offsetLimit("p{$query['page']}", $query['limit']);
        $draftModel = new DraftModel();
        $rows = $draftModel->getWhere($where, '', 'asc', $limit, $offset)->resultArray();
        foreach ($rows as &$row) {
            $row = $apiControler->normalizeOutput($row);
        }
        $result = $out->validate($rows);
        $paging = ApiUtils::numberedPagerInfo(
            $draftModel->getCount($where),
            '/api/v2/drafts',
            $query,
            $in
        );

        return new Data($result, ['paging' => $paging]);
    }

    /**
     * Use a Topcoder Photo on the user' profile.
     * Add/Remove Links in/from a sided menu.
     *
     * @param ProfileController $sender
     * @param array $args
     */
    public function profileController_afterAddSideMenu_handler($sender, $args) {
        $sender->User->Photo = userPhotoDefaultUrl($sender->User, ['Size' => 200]);
        $sideMenu = $sender->EventArguments['SideMenu'];
        $sideMenu->addLink('Options', sprite('SpTopcoder').' '.t('View/Edit My Topcoder Profile'), self::getTopcoderProfileUrl($sender->User->Name));
        $sideMenu->removeLink('Options', sprite('SpPicture').' '.t('Change My Picture'));
        $sideMenu->removeLink('Options', sprite('SpQuote').' '.t('Quote Settings'));
    }

    /**
     * Get a Topcoder Member Profile Url
     * @param $name vanilla user name
     * @return string  profile url
     */
    public static function getTopcoderProfileUrl($name) {
        $topcoderMemberProfileUrl = c('Plugins.Topcoder.MemberProfileURL');
        return $topcoderMemberProfileUrl . '/' . $name;
   }

    /**
     * Get a Topcoder Member Profile
     * @param $name vanilla user name
     * @return null|string  photo url
     */
    public static function getTopcoderProfile($name) {
        $topcoderMembersApiUrl = c('Plugins.Topcoder.BaseApiURL').c('Plugins.Topcoder.MemberApiURI');
        $memberData = @file_get_contents($topcoderMembersApiUrl.'/'.$name);
        if($memberData === false) {
            // Handle errors (e.g. 404 and others)
            return null;
        }
        $memberResponse = json_decode($memberData);
        //Use a photo of Topcoder member if the member with the given user name exists and photoUrl is not null
        if($memberResponse->result->status === 200 && $memberResponse->result->content !== null) {
            return  $memberResponse->result->content;
        }
        return null;
    }

    /**
     * Get a Topcoder Member Id by Topcoder handle
     * @param $name vanilla user name
     * @return null|int
     */
    public static function getTopcoderId($name) {
        $topcoderMembersApiUrl = c('Plugins.Topcoder.BaseApiURL').c('Plugins.Topcoder.MemberApiURI');
        $memberData = @file_get_contents($topcoderMembersApiUrl.'/'.$name);
        if($memberData === false) {
            // Handle errors (e.g. 404 and others)
            return null;
        }
        $memberResponse = json_decode($memberData);
        //Use a photo of Topcoder member if the member with the given user name exists and photoUrl is not null
        if($memberResponse->result->status === 200 && $memberResponse->result->content !== null) {
            return  $memberResponse->result->content->userId;
        }
        return null;
    }

    /**
     * Generate machine to machine token from Auth0
     * @return null|String m2m token
     */
    public static function getM2MToken()
    {
        $TOPCODER_AUTH0_CLIENT_ID = getenv('AUTH0_CLIENT_ID');
        $TOPCODER_AUTH0_CLIENT_SECRET = getenv('AUTH0_CLIENT_SECRET');
        $TOPCODER_AUTH0_AUDIENCE = getenv('AUTH0_AUDIENCE');
        $TOPCODER_AUTH0_URL = getenv('AUTH0_URL');
        $TOPCODER_AUTH0_PROXY_SERVER_URL = getenv('AUTH0_PROXY_SERVER_URL');

        if(!(isset($TOPCODER_AUTH0_CLIENT_ID) &&
            isset($TOPCODER_AUTH0_CLIENT_SECRET) &&
            isset($TOPCODER_AUTH0_AUDIENCE) &&
            isset($TOPCODER_AUTH0_URL) &&
            isset($TOPCODER_AUTH0_PROXY_SERVER_URL))) {
            logMessage(__FILE__,__LINE__,'TopcoderPlugin','getM2MToken()',"M2M Token parameters weren't set");
            throw new InvalidArgumentException("M2M Token parameters weren't set");
        }

        $data = array('grant_type' => 'client_credentials',
            'client_id' => $TOPCODER_AUTH0_CLIENT_ID,
            'client_secret' => $TOPCODER_AUTH0_CLIENT_SECRET,
            'audience' => $TOPCODER_AUTH0_AUDIENCE,
            'auth0_url' => $TOPCODER_AUTH0_URL);

        $m2mOptions = array('http' => array(
            'method' => 'POST',
            'header' => 'Content-type: application/json',
            'content' => json_encode($data)
        ));

        $m2mContext = stream_context_create($m2mOptions);
        try {
            $m2mTokenData = file_get_contents($TOPCODER_AUTH0_PROXY_SERVER_URL, false, $m2mContext);
            $m2mTokenResponse = json_decode($m2mTokenData);
            return $m2mTokenResponse->access_token;
        } catch (Exception $e) {
            logMessage(__FILE__,__LINE__,'TopcoderPlugin','getM2MToken',"M2M token wasn't generated:" .$e.message);
            return null;
        }

    }

    /**
     * Get a Topcoder Roles
     *
     * @param $name Topcoder Handle
     * @return null|string  array of role objects. Example of role object:
     *  {
     *       "id":"3",
     *       "modifiedBy":null,
     *      "modifiedAt":null,
     *       "createdBy":null,
     *       "createdAt":null,
     *       "roleName":"Connect Support"
     *   }
     */
    public static function getTopcoderRoles($name) {
        $topcoderId =  TopcoderPlugin::getTopcoderId($name);
        if ($topcoderId) {
            $token = TopcoderPlugin::getM2MToken();
            if ($token) {
                $topcoderRolesApiUrl = c('Plugins.Topcoder.BaseApiURL') . c('Plugins.Topcoder.RoleApiURI');
                $options = array('http' => array(
                    'method' => 'GET',
                    'header' => 'Authorization: Bearer ' .$token
                ));
                $context = stream_context_create($options);
                $rolesData = file_get_contents($topcoderRolesApiUrl . '?filter=subjectID%3D' . $topcoderId, false, $context);
                if ($rolesData === false) {
                    // Handle errors (e.g. 404 and others)
                    logMessage(__FILE__, __LINE__, 'TopcoderPlugin', 'getTopcoderRoles', "Couldn't get Topcoder roles".json_encode($http_response_header));
                    return null;
                }

                $rolesResponse = json_decode($rolesData);
                if ($rolesResponse->result->status === 200 && $rolesResponse->result->content !== null) {
                     return $rolesResponse->result->content;
                }
            }
        }
        return null;
    }

    /**
     * Check if User has a Topcoder admin role
     *
     * @param $name  username
     * @return boolean true if User has Topcoder admin role
     */
    public static function hasTopcoderAdminRole($name) {
        $roles =  TopcoderPlugin::getTopcoderRoles($name);
        if($roles) {
            $adminRoleNames = array("admin", "administrator");
            foreach ($roles as $role) {
                if (in_array(strtolower($role->roleName), $adminRoleNames)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get a photo url from Topcoder Member Profile
     * @param $name vanilla user name
     * @return null|string  photo url
     */
    public static function getTopcoderPhotoUrl($name) {
        $topcoderProfile = self::getTopcoderProfile($name);
        if($topcoderProfile !== null) {
            return  $topcoderProfile->photoURL;
        }
        return null;
    }


    /**
     * Get a Tocoder rating from Topcoder Member Statistics
     * @param $name
     * @return int|null
     */
    public static function getTopcoderRating($name) {
        $topcoderMembersApiUrl = c('Plugins.Topcoder.BaseApiURL').c('Plugins.Topcoder.MemberApiURI');
        $memberStatsData = @file_get_contents($topcoderMembersApiUrl.'/'.$name.'/stats');
        if($memberStatsData === false) {
            // Handle errors (e.g. 404 and others)
            return null;
        }
        $memberStatsResponse = json_decode($memberStatsData);
        if($memberStatsResponse->result->status === 200 && $memberStatsResponse->result->content[0]->maxRating) {
            return $memberStatsResponse->result->content[0]->maxRating->rating;
        }

        return null;
    }

    /**
     * Get css style based on Topcoder Member Rating
     * @param $rating
     * @return mixed|string
     */
    public static function getRatingCssClass($rating){
        $cssStyles = array('coderTextOrange', 'coderTextWhite', 'coderTextGray',
            'coderTextGreen', 'coderTextBlue', 'coderTextYellow', 'coderTextRed');

        $cssStyle = '';
        if ($rating < 0) {
            $cssStyle = $cssStyles[0];
        } else if ($rating == 0) {
            $cssStyle = $cssStyles[1];
        } else if ($rating > 0 && $rating < 900) {
            $cssStyle = $cssStyles[2];
        } else if ($rating > 899 && $rating < 1200) {
            $cssStyle = $cssStyles[3];
        } else if ($rating > 1199 && $rating < 1500) {
            $cssStyle = $cssStyles[4];
        } else if ($rating > 1499 && $rating < 2200) {
            $cssStyle = $cssStyles[5];
        } else if ($rating > 2199) {
            $cssStyle = $cssStyles[6];
        }

        return $cssStyle;
    }


    public static function getUserPhotoUrl($user) {
        $name = val('Name', $user, null);
        if ($name !== null) {
            $photoUrl = self::getTopcoderPhotoUrl($name);
            return $photoUrl === null? UserModel::getDefaultAvatarUrl(): $photoUrl;
        }
        return UserModel::getDefaultAvatarUrl();
    }
}

if(!function_exists('topcoderRatingCssClass')) {
    /**
     * Take an user name to get rating css style .
     *
     * @return string Returns rating css style
     */
    function topcoderRatingCssClass($name) {
        $topcoderRating = TopcoderPlugin::getTopcoderRating($name);
        if ($topcoderRating != null) {
            $coderStyles = TopcoderPlugin::getRatingCssClass($topcoderRating);
            return $coderStyles;
        }
        return '';
    }
}

if (!function_exists('userBuilder')) {
    /**
     * Take an object & prefix value and convert it to a user object that can be used by userAnchor() && userPhoto().
     *
     * The object must have the following fields: UserID, Name, Photo.
     *
     * @param stdClass|array $row The row with the user extract.
     * @param string|array $userPrefix Either a single string user prefix or an array of prefix searches.
     * @return stdClass Returns an object containing the user.
     */
    function userBuilder($row, $userPrefix = '') {
        $row = (object)$row;
        $user = new stdClass();

        if (is_array($userPrefix)) {
            // Look for the first user that has the desired prefix.
            foreach ($userPrefix as $px) {
                if (property_exists($row, $px.'Name')) {
                    $userPrefix = $px;
                    break;
                }
            }

            if (is_array($userPrefix)) {
                $userPrefix = '';
            }
        }

        $userID = $userPrefix.'UserID';
        $name = $userPrefix.'Name';
        $photo = $userPrefix.'Photo';
        $gender = $userPrefix.'Gender';
        $user->UserID = $row->$userID;
        $user->Name = $row->$name;

        $topcoderPhotoUrl = TopcoderPlugin::getTopcoderPhotoUrl($user->Name);
        if($topcoderPhotoUrl !== null) {
            $user->Photo = $topcoderPhotoUrl;
            $user->PhotoUrl = $topcoderPhotoUrl;
        } else {
            $user->Photo = property_exists($row, $photo) ? $row->$photo : '';
        }

        $user->Email = val($userPrefix.'Email', $row, null);
        $user->Gender = property_exists($row, $gender) ? $row->$gender : null;

        return $user;
    }
}

if (!function_exists('userPhoto')) {
    /**
     * Takes a user object, and writes out an anchor of the user's icon to the user's profile.
     * Use a photoUrl from Topcoder profile
     * @param object|array $user A user object or array.
     * @param array $options
     * @return string HTML.
     */
    function userPhoto($user, $options = []) {
        if (is_string($options)) {
            $options = ['LinkClass' => $options];
        }

        if ($px = val('Px', $options)) {
            $user = userBuilder($user, $px);
        } else {
            $user = (object)$user;
        }

        $linkClass = concatSep(' ', val('LinkClass', $options, ''), 'PhotoWrap');
        $imgClass = val('ImageClass', $options, 'ProfilePhoto');

        $size = val('Size', $options);
        if ($size) {
            $linkClass .= " PhotoWrap{$size}";
            $imgClass .= " {$imgClass}{$size}";
        } else {
            $imgClass .= " {$imgClass}Medium"; // backwards compat
        }

        $fullUser = Gdn::userModel()->getID(val('UserID', $user), DATASET_TYPE_ARRAY);
        $userCssClass = val('_CssClass', $fullUser);
        if ($userCssClass) {
            $linkClass .= ' '.$userCssClass;
        }

        $photoUrl =  val('PhotoUrl', $user);
        $name = val('Name', $fullUser);
        $title = htmlspecialchars(val('Title', $options, $name));

        if ($fullUser && $fullUser['Banned']) {
            $title .= ' ('.t('Banned').')';
        }

        $attributes = [
            'class' => $linkClass,
            'rel' => val('Rel', $options)
        ];

        $userLink = userUrl($fullUser);
        $topcoderProfile = TopcoderPlugin::getTopcoderProfile($name);
        if($topcoderProfile !== null) {
            $attributes['target'] = '_blank';


            $userLink = TopcoderPlugin::getTopcoderProfileUrl($name);
            $topcoderPhotoUrl = $topcoderProfile->photoURL;
            if ($topcoderPhotoUrl !== null) {
                $photoUrl = $topcoderPhotoUrl;
            }
        }

        $photoUrl = isset($photoUrl) && !empty(trim($photoUrl)) ? $photoUrl: UserModel::getDefaultAvatarUrl();
        $href = (val('NoLink', $options)) ? '' : ' href="'.url($userLink).'"';

        return '<a title="'.$title.'"'.$href.attribute($attributes).'>'
            .img($photoUrl, ['alt' => $name, 'class' => $imgClass])
            .'</a>';
    }
}

if (!function_exists('userPhotoDefaultUrl')) {
    /**
     * Take a user object an return the URL to their photo.
     *
     * @param object|array $user
     * @return string
     */
    function userPhotoDefaultUrl($user) {
        return TopcoderPlugin::getUserPhotoUrl($user);
    }
}

if (!function_exists('userPhotoUrl')) {
    /**
     * Take a user object an return the URL to their photo.
     *
     * @param object|array $user
     * @return string
     */
    function userPhotoUrl($user) {
        return TopcoderPlugin::getUserPhotoUrl($user);
    }
}

if (!function_exists('topcoderUserUrl')) {
    /**
     * Return the URL for a topcoder user.
     *
     * @param array|object $user The user to get the url for.
     * @param string $px The prefix to apply before fieldnames.
     * @return string The url suitable to be passed into the url() function.
     * @since 2.1
     */
    function topcoderUserUrl($user, $px = '') {
        $userName = val($px.'Name', $user);
        return TopcoderPlugin::getTopcoderProfileUrl(rawurlencode($userName));
    }
}


if (!function_exists('userAnchor')) {
    /**
     * Take a user object, and writes out an anchor of the user's name to the user's profile.
     *
     * @param array|object $user
     * @param null $cssClass
     * @param null $options
     * @return string
     */
    function userAnchor($user, $cssClass = null, $options = null) {
        static $nameUnique = null;
        if ($nameUnique === null) {
            $nameUnique = c('Garden.Registration.NameUnique');
        }

        if (is_array($cssClass)) {
            $options = $cssClass;
            $cssClass = null;
        } elseif (is_string($options)) {
            $options = ['Px' => $options];
        }

        $px = val('Px', $options, '');
        $name = val($px.'Name', $user, t('Unknown'));
        $text = val('Text', $options, htmlspecialchars($name)); // Allow anchor text to be overridden.

        $attributes = [
            'class' => $cssClass,
            'rel' => val('Rel', $options)
          ];
        if (isset($options['title'])) {
            $attributes['title'] = $options['title'];
        }

        // Go to Topcoder user profile link instead of Vanilla profile link
        $userUrl = topcoderUserUrl($user, $px);

        $topcoderRating = TopcoderPlugin::getTopcoderRating($name);
        if($topcoderRating != null) {
            $coderStyles = TopcoderPlugin::getRatingCssClass($topcoderRating);
            $attributes['class'] = $attributes['class'].' '.$coderStyles ;
        }

        $isTopcoderAdmin = TopcoderPlugin::hasTopcoderAdminRole($name);
        if($isTopcoderAdmin) {
            $attributes['class'] = $attributes['class'].' '. 'topcoderAdmin' ;
        }
        return '<a href="'.htmlspecialchars(url($userUrl)).'"'.attribute($attributes).'>'.$text.'</a>';
    }
}

if (!function_exists('writeActivity')) {
    // The issue: writesActivity fires 'BeforeActivity' but the author link with the photo has been rendered.
    // So profileController_BeforeActivity_handler couldn't help to overwrite the properties.
    // This function is copied from \applications\dashboard\views\activity\helper_functions.php
    // and used to render Activities on Profile page.
    function writeActivity($activity, $sender, $session) {
        $activity = (object)$activity;
        // If this was a status update or a wall comment, don't bother with activity strings
        $activityType = explode(' ', $activity->ActivityType); // Make sure you strip out any extra css classes munged in here
        $activityType = $activityType[0];
        $author = userBuilder($activity, 'Activity');
        $photoAnchor = '';

        if ($activity->Photo) {
            //FIX: Use the photoUrl from the author
            $photoAnchor = anchor(
                img($author->Photo, ['class' => 'ProfilePhoto ProfilePhotoMedium', 'aria-hidden' => 'true']),
                $activity->PhotoUrl, 'PhotoWrap');
        }

        $cssClass = 'Item Activity Activity-'.$activityType;
        if ($photoAnchor != '')
            $cssClass .= ' HasPhoto';

        $format = val('Format', $activity);
        if (!$format) {
            $format = 'html';
        }

        $title = '';
        $excerpt = Gdn_Format::to($activity->Story, $format);

        if ($activity->NotifyUserID > 0 || !in_array($activityType, ['WallComment', 'WallPost', 'AboutUpdate'])) {
            $title = '<div class="Title" role="heading" aria-level="3">'.val('Headline', $activity).'</div>';
        } else if ($activityType == 'WallPost') {
            $regardingUser = userBuilder($activity, 'Regarding');
            $photoAnchor = userPhoto($regardingUser);
            $title = '<div class="Title">'
                .userAnchor($regardingUser, 'Name')
                .' <span>&rarr;</span> '
                .userAnchor($author, 'Name')
                .'</div>';

            if (!$format)
                $excerpt = Gdn_Format::display($excerpt);
        } else {
            $title = userAnchor($author, 'Name');
            if (!$format)
                $excerpt = Gdn_Format::display($excerpt);
        }
        $sender->EventArguments['Activity'] = &$activity;
        $sender->EventArguments['CssClass'] = &$cssClass;
        $sender->fireEvent('BeforeActivity');
        ?>
    <li id="Activity_<?php echo $activity->ActivityID; ?>" class="<?php echo $cssClass; ?>">
        <?php
        if (ActivityModel::canDelete($activity)) {
            echo '<div class="Options">'.anchor('&times;', 'dashboard/activity/delete/'.$activity->ActivityID.'/'.$session->transientKey().'?Target='.urlencode($sender->SelfUrl), 'Delete').'</div>';
        }
        if ($photoAnchor != '') {
            ?>
            <div class="Author Photo"><?php echo $photoAnchor; ?></div>
        <?php } ?>
        <div class="ItemContent Activity">
            <?php echo $title; ?>
            <?php echo wrapIf($excerpt, 'div', ['class' => 'Excerpt userContent']); ?>
            <?php
            $sender->EventArguments['Activity'] = $activity;
            $sender->fireAs('ActivityController')->fireEvent('AfterActivityBody');

            // Reactions stub
            if (in_array(val('ActivityType', $activity), ['Status', 'WallPost']))
                writeReactions($activity);
            ?>
            <div class="Meta">
                <span class="MItem DateCreated"><?php echo Gdn_Format::date($activity->DateInserted); ?></span>
                <?php
                $sharedString = FALSE;
                $iD = val('SharedNotifyUserID', $activity->Data);
                if (!$iD)
                    $iD = val('CommentNotifyUserID', $activity->Data);

                if ($iD)
                    $sharedString = formatString(t('Comments are between {UserID,you}.'), ['UserID' => [$activity->NotifyUserID, $iD]]);

                $allowComments = $activity->NotifyUserID < 0 || $sharedString;


                if ($allowComments && $session->checkPermission('Garden.Profiles.Edit')) {
                    echo '<span class="MItem AddComment">'
                        .anchor(t('Activity.Comment', 'Comment'), '#CommentForm_'.$activity->ActivityID, 'CommentOption')
                        .'</span>';
                }

                if ($sharedString) {
                    echo ' <span class="MItem"><i>'.$sharedString.'</i></span>';
                }

                $sender->fireEvent('AfterMeta');
                ?>
            </div>
        </div>
        <?php
        $comments = val('Comments', $activity, []);
        if (count($comments) > 0) {
            echo '<ul class="DataList ActivityComments">';
            foreach ($comments as $comment) {
                writeActivityComment($comment, $activity);
            }
        } else {
            echo '<ul class="DataList ActivityComments Hidden">';
        }

        if ($session->checkPermission('Garden.Profiles.Edit')):
            ?>
            <li class="CommentForm">
                <?php
                echo anchor(t('Write a comment'), '/dashboard/activity/comment/'.$activity->ActivityID, 'CommentLink');
                $commentForm = Gdn::factory('Form');
                $commentForm->setModel($sender->ActivityModel);
                $commentForm->addHidden('ActivityID', $activity->ActivityID);
                $commentForm->addHidden('Return', Gdn_Url::request());
                echo $commentForm->open(['action' => url('/dashboard/activity/comment'), 'class' => 'Hidden']);
                echo '<div class="TextBoxWrapper">'.$commentForm->textBox('Body', ['MultiLine' => true, 'value' => '']).'</div>';

                echo '<div class="Buttons">';
                echo $commentForm->button('Comment', ['class' => 'Button Primary']);
                echo '</div>';

                echo $commentForm->close();
                ?></li>
        <?php
        endif;

        echo '</ul>';
        ?>
        </li>
        <?php
    }
}

