<?php
/**
 * Class TopcoderPlugin
 */

if (!class_exists('Auth0\SDK\Auth0')){
    require __DIR__ . '/vendor/autoload.php';
}

use Garden\Schema\Schema;
use Garden\Web\Data;
use Garden\Web\Exception\ClientException;
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
use Vanilla\Utility\ModelUtils;


class TopcoderPlugin extends Gdn_Plugin {

    const ROLE_TYPE_TOPCODER = 'topcoder';
    const ROLE_TOPCODER_CONNECT_ADMIN = 'Connect Admin';
    const ROLE_TOPCODER_ADMINISTRATOR = 'administrator';
    const ROLE_TOPCODER_COPILOT = 'copilot';
    const ROLE_TOPCODER_CONNECT_COPILOT = 'Connect Copilot';
    const ROLE_TOPCODER_CONNECT_MANAGER = 'Connect Manager';
    const DEFAULT_EXPIRATION = 86400;

    const GLOBAl_TOPCODER_ROLES = [
            self::ROLE_TOPCODER_COPILOT => [
                'Role' => self::ROLE_TOPCODER_COPILOT,
                'Type' => self::ROLE_TYPE_TOPCODER,
                'Garden.Uploads.Add' => 1
            ],

            self::ROLE_TOPCODER_CONNECT_COPILOT => [
                'Role' => self::ROLE_TOPCODER_CONNECT_COPILOT,
                'Type' => self::ROLE_TYPE_TOPCODER,
                'Garden.Uploads.Add' => 1
            ],

            self::ROLE_TOPCODER_ADMINISTRATOR => [
                'Role' => self::ROLE_TOPCODER_ADMINISTRATOR,
                'Type' => self::ROLE_TYPE_TOPCODER,
                // all permissions
            ],

            self::ROLE_TOPCODER_CONNECT_ADMIN => [
                'Role' => self::ROLE_TOPCODER_CONNECT_ADMIN,
                'Type' => self::ROLE_TYPE_TOPCODER,
                 // all permissions
            ]
    ];
    private $providerKey;
    private $provider;
    private $cacheHandler;

    const ERROR_CODES = [ 'TokenNotFound' => 'Token wasn\'t found.',
        'TokenNotDecoded' => 'Could\'not decode a token.',
        'InvalidTokenIssuer'=>'Invalid Token Issuer.',
        'TokenRefreshFailed' => 'Couldn\'t  get a refresh token.',
        'TokenVerificationFailed' => 'Verification of the token was failed.',
        'UsernameClaimNotFound' => 'Couldn\'t get the requested claim.',
        'VanillaUserNotFound' => 'Sorry, no Vanilla account could be found related to the Topcoder username.'];

    public function __construct() {
        parent::__construct();
        $this->providerKey = 'topcoder';
    }

    /**
     * Database updates.
     */
    public function structure() {
        include __DIR__.'/structure.php';
    }

    /**
     * Run once on enable.
     *
     * @throws Gdn_UserException
     */
    public function setup() {
        // Initial data hasn't been inserted
        if(!c('Garden.Installed')) {
            return;
        }

        $this->structure();

        $model = new Gdn_AuthenticationProviderModel();
        $provider = $model->getID('topcoder');
        if(!$provider) {
            $provider['AuthenticationKey'] = 'topcoder';
            $provider['AuthenticationSchemeAlias'] = 'topcoder';
            $provider['SignInUrl'] = c('Plugins.Topcoder.AuthenticationProvider.SignInUrl');
            $provider['SignOutUrl'] = c('Plugins.Topcoder.AuthenticationProvider.SignOutUrl');
            $provider['RegisterUrl'] = c('Plugins.Topcoder.AuthenticationProvider.RegisterUrl');
            $provider['Active'] = 1;
            $provider['Default'] = 1;
            $provider['IsDefault'] = 1;
            $model->save($provider);
        }else {
            $model->update(['SignInUrl' => c('Plugins.Topcoder.AuthenticationProvider.SignInUrl'),
                'SignOutUrl' => c('Plugins.Topcoder.AuthenticationProvider.SignOutUrl'),
                 'RegisterUrl' => c('Plugins.Topcoder.AuthenticationProvider.RegisterUrl')
                ], ['AuthenticationKey' => 'topcoder']);
        }

      //  $this->initDefaultVanillaRoles();
      //  $this->initDefaultTopcoderRoles();

        $this->initCache();
    }

    public function onDisable() {
        if($this->cacheHandler) {
            $this->cacheHandler->clear();
        }
    }

    /**
     * Init a cache to store the contents of the public keys used to check the token signature
     */
    private function initCache() {
        $JWKS_PATH_CACHE = PATH_ROOT. "/jwks";
        if (!file_exists($JWKS_PATH_CACHE)) {
            if(!mkdir($JWKS_PATH_CACHE, 0777)) {
                Logger::event(
                    'topcoder_plugin_logging',
                    Logger::ERROR,
                    'Couldn\'t create a cache directory',
                    ['Directory' => $JWKS_PATH_CACHE]
                );
                return;
            }
        }

        if(isWritable($JWKS_PATH_CACHE)) {
            $this->cacheHandler = new FileCache($JWKS_PATH_CACHE, self::DEFAULT_EXPIRATION);
        }
    }

    /**
     * Init all default Topcoder roles and set up permissions
     */
    private function initDefaultTopcoderRoles() {
        $defaultTopcoderRoles = TopcoderPlugin::getAllTopcoderRoles();
        $roleNames = array_column($defaultTopcoderRoles, 'roleName');
        $this->checkTopcoderRoles($roleNames);
    }

    /**
     * Init all default Vanilla roles and set up permissions
     */
    private function initDefaultVanillaRoles() {
        $permissionModel = Gdn::permissionModel();

        // Update Vanilla Guest role
        $permissions = $permissionModel->getGlobalPermissions(2); // Guest role
        unset($permissions['PermissionID']);
        foreach ($permissions as $key => $value) {
              $permissions[$key] = 0;
        }
        $permissions['Role'] = RoleModel::TYPE_GUEST;
        $permissionModel->save($permissions);

        // Update Vanilla Member role
        $permissionModel->save( [
            'Role' => 'Member',
            'Garden.Uploads.Add' => 0
        ]);

        $permissionModel->clearPermissions();
    }

    /**
     * The settings page for the topcoder plugin.
     *
     * @param Gdn_Controller $sender
     */
    public function settingsController_topcoder_create($sender) {
        $sender->permission('Garden.Settings.Manage');
        $sender->setData('Title', sprintf(t('%s Settings'), 'Topcoder'));

        $cf = new TopcoderConfigurationModule($sender);

        // Form submission handling
        if(Gdn::request()->isAuthenticatedPostBack()) {
            $cf->form()->validateRule('Plugins.Topcoder.BaseApiURL', 'ValidateRequired', t('You must provide Base API URL.'));
            $cf->form()->validateRule('Plugins.Topcoder.MemberApiURI', 'ValidateRequired', t('You must provide MemberAPI URI.'));
            $cf->form()->validateRule('Plugins.Topcoder.RoleApiURI', 'ValidateRequired', t('You must provide Role API URI.'));
            $cf->form()->validateRule('Plugins.Topcoder.ResourceRolesApiURI', 'ValidateRequired', t('You must provide Resource Roles API URI.'));
            $cf->form()->validateRule('Plugins.Topcoder.ResourcesApiURI', 'ValidateRequired', t('You must provide Resources API URI.'));
            $cf->form()->validateRule('Plugins.Topcoder.MemberProfileURL', 'ValidateRequired', t('You must provide Member Profile URL.'));
            if($cf->form()->getFormValue('Plugins.Topcoder.UseTopcoderAuthToken')  == 1) {
                $cf->form()->validateRule('Plugins.Topcoder.AuthenticationProvider.SignInUrl', 'ValidateRequired', t('You must provide SignIn URL.'));
                $cf->form()->validateRule('Plugins.Topcoder.AuthenticationProvider.SignOutUrl', 'ValidateRequired', t('You must provide SignOut URL.'));
                $cf->form()->validateRule('Plugins.Topcoder.AuthenticationProvider.RegisterUrl', 'ValidateRequired', t('You must provide Register URL.'));
                $cf->form()->validateRule('Plugins.Topcoder.SSO.RefreshTokenURL', 'ValidateRequired', t('You must provide Refresh Token URL.'));
                $cf->form()->validateRule('Plugins.Topcoder.SSO.CookieName', 'ValidateRequired', t('You must provide Cookie Name.'));
                $cf->form()->validateRule('Plugins.Topcoder.SSO.TopcoderHS256.UsernameClaim', 'ValidateRequired', t('You must provide Username Claim for HS256 JWT.'));
                $cf->form()->validateRule('Plugins.Topcoder.SSO.TopcoderRS256.UsernameClaim', 'ValidateRequired', t('You must provide Username Claim for RS256 JWT.'));
                $cf->form()->validateRule('Plugins.Topcoder.AuthenticationProvider.SignInUrl', 'ValidateUrl','You must provide valid SignIn URL.');
                $cf->form()->validateRule('Plugins.Topcoder.AuthenticationProvider.SignOutUrl', 'ValidateUrl','You must provide valid SignOut URL.');
                $cf->form()->validateRule('Plugins.Topcoder.AuthenticationProvider.RegisterUrl', 'ValidateUrl','You must provide valid Register URL.');
                $cf->form()->validateRule('Plugins.Topcoder.SSO.RefreshTokenURL', 'ValidateUrl','You must provide valid Refresh Token URL.');
            }
        }

        $cf->initialize([
            'Plugins.Topcoder.BaseApiURL' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'TopCoder Base API URL'],
            'Plugins.Topcoder.MemberApiURI' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Member API URI'],
            'Plugins.Topcoder.RoleApiURI' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Role API URI'],
            'Plugins.Topcoder.ResourceRolesApiURI' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Resource Roles API URI'],
            'Plugins.Topcoder.ResourcesApiURI' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Resources API URI'],
            'Plugins.Topcoder.MemberProfileURL' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Member Profile URL'],
            'Plugins.Topcoder.UseTopcoderAuthToken' => ['Control' => 'CheckBox', 'Default' => false, 'Description' => 'Use Topcoder access token to log in to Vanilla'],
            'Plugins.Topcoder.AuthenticationProvider.SignInUrl' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder SignIn URL'],
            'Plugins.Topcoder.AuthenticationProvider.SignOutUrl' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder SignOut URL'],
            'Plugins.Topcoder.AuthenticationProvider.RegisterUrl' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Register URL'],
            'Plugins.Topcoder.AuthenticationProvider.IsDefault' => ['Control' => 'CheckBox', 'Default' => true, 'Description' => 'Use Topcoder Auth0 provider'],
            'Plugins.Topcoder.SSO.RefreshTokenURL' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Refresh Token URL for RS256 JWT'],
            'Plugins.Topcoder.SSO.CookieName' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Cookie Name'],
            'Plugins.Topcoder.SSO.TopcoderHS256.UsernameClaim' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Username Claim for HS256 JWT'],
            'Plugins.Topcoder.SSO.TopcoderRS256.UsernameClaim' => ['Control' => 'TextBox', 'Default' => '', 'Description' => 'Topcoder Username Claim for RS256 JWT'],
        ]);

        $cf->renderAll();
    }


    /** ------------------- Authentication Provider Related Methods --------------------- */

    /**
     * Check authentication provider table to see if this is the default method for logging in.
     *
     * @return bool Return the value of the IsDefault row of GDN_UserAuthenticationProvider .
     */
    public function isDefault() {
        $provider = $this->provider();
        return val('IsDefault', $provider);
    }

    /**
     * Check if there is enough data to connect to an authentication provider.
     *
     * @return bool True if there is url and others
     */
    public function isConfigured() {
        $provider = $this->provider();
        $signInURL = val('SignInUrl', $provider);
        $signOutURL = val('SignOutUrl', $provider);
        $cookieName = c('Plugins.Topcoder.SSO.CookieName', null);
        $claim = c('Plugins.Topcoder.SSO.UsernameClaim', null);
        $isConfigured = isset($signInURL) &&  isset($signOutURL) &&
            isset($cookieName) &&
            isset($claim);
        return $isConfigured;
    }

    /**
     *  Return all the information saved in provider table.
     *
     * @return array Stored provider data.
     */
    public function provider() {
        if (!$this->provider) {
            $this->provider = Gdn_AuthenticationProviderModel::getProviderByKey($this->providerKey);
        }

        return $this->provider;
    }

    /**
     *  Get provider key.
     *
     * @return string Provider key.
     */
    public function getProviderKey() {
        return $this->providerKey;
    }

    /**
     * Authenticate a user using the JWT supplied from the cookies
     */
    public function gdn_auth_startAuthenticator_handler() {
        // Skip it if Vanilla Installation setup
        if(!c('Garden.Installed')) {
            return;
        }

        // if(!$this->isDefault()) {
        //     self::log('Topcoder Auth0 is not a default provider', []);
        //     return;
        // }

       self::log('TopcoderPlugin: gdn_auth_startAuthenticator_handler', ['Path' => Gdn::request()->path()]);

        // Ignore EntryController endpoints and ApiController endpoints.
        // AccessToken for /api will be checked in class.hooks.php
        if (stringBeginsWith(Gdn::request()->getPath(), '/api/') || stringBeginsWith(Gdn::request()->getPath(), '/entry/')) {
            return;
        }

        $cookieName = c('Plugins.Topcoder.SSO.CookieName');
       self::log('Cookie Name', ['value' => $cookieName]);

        $cookiesToken = isset($_COOKIE[$cookieName]) ? $_COOKIE[$cookieName] : null;

        $headersToken = $this->getBearerToken();
        $accessToken = $headersToken ? $headersToken : $cookiesToken;

        if ($cookiesToken) {
           self::log('Token from Cookies', ['value' => $cookiesToken]);
        }
        if ($headersToken) {
           self::log('Token from Headers', ['value' => '' . $headersToken]);
        }

        if ($accessToken) {
           self::log('Using Token', ['value' => $accessToken]);
        } else {
           self::log('Token wasn\'t found', []);
            $this->fireEvent('GuestSignIn', []);
            return;
        }

        $useTopcoderAuthToken = c('Plugins.Topcoder.UseTopcoderAuthToken');

        if ($useTopcoderAuthToken && $accessToken) {

            $VALID_ISSUERS = explode(",", c('Plugins.Topcoder.ValidIssuers'));
           self::log('Valid Issuers:', ['result' => $VALID_ISSUERS]);

            $decodedToken = null;
            try {
                $decodedToken = (new Parser())->parse((string)$accessToken);
            } catch (\Exception $e) {
               self::log('Could\'not decode a token', ['Error' => $e . getMessage]);
                $this->fireEvent('BadSignIn', [
                    'jwt' =>  $accessToken,
                    'ErrorCode' => 'TokenNotDecoded',
                ]);
                return;
            }

           self::log('Decoded Token', ['Headers' => $decodedToken->getHeaders(), 'Claims' => $decodedToken->getClaims()]);
            $signatureVerifier = null;
            $issuer = $decodedToken->hasClaim('iss') ? $decodedToken->getClaim('iss') : null;
            if ($issuer === null || !in_array($issuer, $VALID_ISSUERS)) {
               self::log('Invalid token issuer', ['Found issuer' => $issuer, 'Valid issuers' => $VALID_ISSUERS]);
                $this->fireEvent('BadSignIn', [
                    'jwt' =>  $accessToken,
                    'ErrorCode' => 'InvalidTokenIssuer',
                ]);
                return;
            }

           self::log('Issuer', ['Issuer' => $issuer]);

            $AUTH0_AUDIENCE = null;
            $USERNAME_CLAIM = null;
            if ($decodedToken->getHeader('alg') === 'RS256') {
                $AUTH0_AUDIENCE = c('Plugins.Topcoder.SSO.TopcoderRS256.ID');
                $USERNAME_CLAIM = c('Plugins.Topcoder.SSO.TopcoderRS256.UsernameClaim');
                $jwksUri = $issuer . '.well-known/jwks.json';
                $jwksHttpOptions = ['base_uri' => $jwksUri];
                $jwksFetcher = new JWKFetcher($this->cacheHandler, $jwksHttpOptions);
                $signatureVerifier = new AsymmetricVerifier($jwksFetcher);

            } else if ($decodedToken->getHeader('alg') === 'HS256') {
                $USERNAME_CLAIM = c('Plugins.Topcoder.SSO.TopcoderHS256.UsernameClaim');
                $AUTH0_AUDIENCE = c('Plugins.Topcoder.SSO.TopcoderHS256.ID');
                $CLIENT_H256SECRET = c('Plugins.Topcoder.SSO.TopcoderHS256.Secret');
                $signatureVerifier = new SymmetricVerifier($CLIENT_H256SECRET);
            } else {
                $this->fireEvent('BadSignIn', [
                    'jwt' =>  $accessToken,
                    'ErrorCode' => 'Not supported "alg"',
                ]);
                return;
            }

            $tokenVerifier = new IdTokenVerifier(
                $issuer,
                $AUTH0_AUDIENCE,
                $signatureVerifier
            );

            try {
                $tokenVerifier->verify($accessToken);
               self::log('Verification of the token was successful', []);
            } catch (\Auth0\SDK\Exception\InvalidTokenException $e) {
                if ($decodedToken->getHeader('alg') === 'HS256' && strpos($e->getMessage(), 'Audience (aud) claim must be a string)') === 0) {
                    // FIX: a Topcoder payload (HS256) doesn't have 'aud'
                   self::log('Verification of the HS256 token wasn\'t successful', ['Error' => $e . getMessage]);
                }
            } catch (\Exception $e) {
                // Silently Token Refresh Logic for HS256 JWT
                if ($decodedToken->getHeader('alg') === 'HS256' && strpos($e->getMessage(), "Expiration Time") === 0) {
                   self::log('The token was expired', []);
                    $refreshToken = $this->getRefreshToken($accessToken);
                    if ($refreshToken) {
                        setcookie('refresh_token', $refreshToken);
                    } else {
                        Gdn::session()->end(Gdn::authenticator());
                       self::log('Couldn\'t  get a refresh token. Ending the current session...', []);
                        $this->fireEvent('BadSignIn', [
                            'jwt' =>  $accessToken,
                            'ErrorCode' => 'TokenRefreshFailed',
                        ]);
                        return;
                    }
                } else {
                   self::log('Verification of the token was failed', ['Error' => $e . getMessage]);
                    $this->fireEvent('BadSignIn', [
                        'jwt' =>  $accessToken,
                        'ErrorCode' => 'TokenVerificationFailed',
                    ]);
                    return;
                }
            }

           self::log('Username Claim', ['value' => $USERNAME_CLAIM]);

            if (!$decodedToken->hasClaim($USERNAME_CLAIM)) {
               self::log('Couldn\'t get the requested claim', ['Claim' => $USERNAME_CLAIM]);
                $this->fireEvent('BadSignIn', [
                    'jwt' =>  $accessToken,
                    'ErrorCode' => 'UsernameClaimNotFound',
                ]);
                return;
            }

            $topcoderRoles = $this->getRolesClaim($decodedToken);

            $this->checkTopcoderRoles($topcoderRoles);

            $topcoderUserName = $decodedToken->getClaim($USERNAME_CLAIM);
            if ($topcoderUserName) {
               self::log('Trying to signIn ...', ['username' => $topcoderUserName]);

                $userModel = new UserModel();
                $user = $userModel->getByUsername($topcoderUserName);
                $userID = null;
                if ($user) {
                    $userID = val('UserID', $user);
                   self::log('Found Vanilla User:', ['Vanilla UserID' => $userID]);
                } else {
                   self::log('Vanilla User was not found', []);
                    if($decodedToken->hasClaim('email')) {
                        $email = $decodedToken->getClaim('email');
                        $userData = [
                            "Email" => $email,
                            "EmailConfirmed" => true,
                            "Name" => $topcoderUserName,
                            "Password" => $this->getRandomString(),
                            "Photo" => null,
                        ];

                        $settings = [
                            'NoConfirmEmail' => true,
                            'ValidateName' => false
                        ];
                        $userID = $userModel->save($userData, $settings);

                        $roles  = RoleModel::getByName($topcoderRoles);
                        // Add all Topcoder roles from a payload and Vanilla member
                        // User must have at least one role with the 'SignIn.Allow' permission to sign in
                        $roleIDs = array_merge(array_keys($roles), [8]);
                        $userModel->saveRoles($userID, $roleIDs, false);

                        try {
                            ModelUtils::validationResultToValidationException($userModel, Gdn::locale(), true);
                           self::log('Vanilla User was added', ['UserID' => $userID]);
                        } catch (\Garden\Schema\ValidationException $e) {
                           self::log('Couldn\'t add a new user',['Topcoder Username' => $topcoderUserName, 'error' => $e->getMessage()]);
                            Logger::event(
                                'sso_logging',
                                Logger::ERROR,
                                'Couldn\'t add a new user',
                                ['Topcoder Username' => $topcoderUserName, 'error' => $e->getMessage()]
                            );
                        }
                        if($userID === false) {
                            $this->fireEvent('GuestSignIn', []);
                            return;
                        }
                    }

                }

                if ($userID) {
                    $this->syncTopcoderRoles($userID,$topcoderRoles);
                    Gdn::session()->start($userID, true);
                    $userModel->fireEvent('AfterSignIn');
                    $session = Gdn::session();
                    if (!$session->isValid()) {
                       self::log('The session could not be started.', []);
                        throw new ClientException('The session could not be started.', 401);
                    }
                } else {
                   self::log('Go with the next Vanilla Authenticator', []);
                }
            } else {
               self::log('Topcoder username from the claim is empty', ['USERNAME_CLAIM' => $USERNAME_CLAIM]);
            }
        } else {
           self::log('Topcoder Access token is not used. Use a default Vanilla Authenticator', []);
        }
    }

    /**
     * Get a role claim
     * @param $decodedToken
     * @return array
     */
    private function getRolesClaim($decodedToken) {
        $claims = $decodedToken->getClaims();
        $keys = array_keys($claims);
        foreach ($keys as $key) {
            if(stringEndsWith($key, '/roles',false)) {
                return $decodedToken->getClaim($key);
            }
        }
        return [];
    }

    /**
     * Check if a role exists in Vanilla. if a role doesn't exist to add it
     * @param $roles array of role names
     */
    private function checkTopcoderRoles($roles) {

        $roleModel = new RoleModel();
        $topcoderRoles = $roleModel->getByType(TopcoderPlugin::ROLE_TYPE_TOPCODER)->resultArray();
        $existingRoles = array_column($topcoderRoles, 'Name');
        $missingRoles = array_diff($roles, $existingRoles);

        foreach ($missingRoles as $newRole) {
            $this->defineRole(['Name' => $newRole, 'Type' => self::ROLE_TYPE_TOPCODER,  'Deletable' => '1',
                'CanSession' => '1', 'Description' => t($newRole.' Description', 'Added by Topcoder plugin')]);
        }
    }

    /**
     * Create a new role
     * @param $values
     */

    private function defineRole($values) {
        if(strlen($values['Name']) == 0) {
            return;
        }

        $roleModel = new RoleModel();

        // Check to see if there is a role with the same name and type.
        $roleID = $roleModel->SQL->getWhere('Role', ['Name' => $values['Name'], 'Type' => $values['Type']])->value('RoleID', null);

        if (is_null($roleID)) {
            // Figure out the next role ID.
            $maxRoleID = $roleModel->SQL->select('r.RoleID', 'MAX')->from('Role r')->get()->value('RoleID', 0);
            $roleID = $maxRoleID + 1;
            $values['RoleID'] = $roleID;

            // Insert the role.
            $roleModel->SQL->insert('Role', $values);

            // Update Topcoder role with permissions
            if(array_key_exists($values['Name'],self::GLOBAl_TOPCODER_ROLES)) {

                $permissionModel = Gdn::permissionModel();
                $permissions = $permissionModel->getGlobalPermissions($roleID);

                unset($permissions['PermissionID']);

                if($values['Name'] == self::ROLE_TOPCODER_CONNECT_ADMIN || $values['Name'] == self::ROLE_TOPCODER_ADMINISTRATOR) {
                    // Add all permissions
                    foreach ($permissions as $key => $value) {
                        $permissions[$key] = 1;
                    }
                } else {
                    // Update permissions
                    $globalRolePermissions = self::GLOBAl_TOPCODER_ROLES[$values['Name']];
                    foreach ($permissions as $key => $value) {
                        $permissions[$key] = array_key_exists($key, $globalRolePermissions)? $globalRolePermissions[$key]:$value;
                    }
                }

                $permissions['Role'] = $values['Name'];
                $permissions['Type'] = $values['Type'];
                $permissionModel->save($permissions, true);

                // Update global category permissions
                if($values['Name'] == self::ROLE_TOPCODER_CONNECT_ADMIN || $values['Name'] == self::ROLE_TOPCODER_ADMINISTRATOR) {
                    $categoryPermissions = $permissionModel->getJunctionPermissions(
                        ['JunctionID' => -1, 'RoleID' => $roleID],
                        'Category'
                    );

                    foreach ($categoryPermissions as $categoryPermission) {
                        foreach ($categoryPermission as $key => $value) {
                            // Update Vanilla.Discussions.View and so on
                            if (stringBeginsWith($key, 'Vanilla.')) {
                                $categoryPermission[$key] = 1;
                            }
                        }
                        $categoryPermission['Role'] = $values['Name'];
                        $categoryPermission['Type'] = $values['Type'];
                        $permissionModel->save($categoryPermission);
                    }
                }
            }
        }

        $roleModel->clearCache();
    }

    /**
     * Sync a list of Topcoder roles for an user
     * @param $userID
     * @param $roles array a list of role names
     *
     */
    private function syncTopcoderRoles($userID, $roles) {
        $userModel = new UserModel();
        $newRoles  = TopcoderPlugin::getRoles($roles, TopcoderPlugin::ROLE_TYPE_TOPCODER);
        $newRoleIDs = array_keys($newRoles);

        $currentRoles = $userModel->getRoles($userID)->resultArray();
        $prevVanillaRoleIDs = array_column($currentRoles, 'RoleID');

        $vanillaRoles = array_filter($currentRoles, function($o) {
            return $o['Type'] != TopcoderPlugin::ROLE_TYPE_TOPCODER;
        });
        $currentVanillaRoleIDs = array_column($vanillaRoles, 'RoleID');
        $mergedRoleIDs = array_unique(array_merge($newRoleIDs, $currentVanillaRoleIDs));
        $result = array_diff($mergedRoleIDs,$prevVanillaRoleIDs);

        // Update roleIDs if there are any changes only
        if(count($result) > 0) {
            $userModel->saveRoles($userID, $mergedRoleIDs, false);
        }
    }

    /**
     * Get a role by name and type.
     *
     * @param array|string $names
     * @param $type string a role type
     * @param null $missing a list of missing roles
     * @return array
     */
    public static function getRoles($names, $type, &$missing = null) {
        if (is_string($names)) {
            $names = explode(',', $names);
            $names = array_map('trim', $names);
        }

        // Make a lookup array of the names.
        $names = array_unique($names);
        $names = array_combine($names, $names);
        $names = array_change_key_case($names);

        $roles = RoleModel::roles();
        $result = [];
        foreach ($roles as $roleID => $role) {
            $name = strtolower($role['Name']);

            if (isset($names[$name]) && $type == $role['Type']) {
                $result[$roleID] = $role;
                unset($names[$name]);
            }
        }

        $missing = array_values($names);

        return $result;
    }

    public function base_afterSignIn_handler($sender, $args) {
       self::log('base_afterSignIn_handler', []);
        if(!Gdn::session()->isValid()) {
            throw new ClientException('The session could not be started', 401);
        }
    }

    /**
     * Missing tokens
     * @param $sender
     * @param $args
     */
    public function base_guestSignIn_handler($sender, $args) {
       self::log('base_guestSignIn_handler', []);
        $this->startSessionAsGuest($sender, $args);
    }

    /**
     * Handle any token issues
     * @param $sender
     * @param $args
     */
    public function base_badSignIn_handler($sender, $args) {
       self::log('base_badSignIn_handler', []);
        $this->startSessionAsGuest($sender, $args);
    }

    /**
     * Start a new session as Guest
     * @param $sender
     * @param $args
     */
    private function startSessionAsGuest($sender, $args) {
        try {
            if (isset($_COOKIE['Vanilla'])) {
                unset($_COOKIE['Vanilla']);
                setcookie('Vanilla', null, -1, '/');
            }
            if (Gdn::session()->isValid()) {
                Gdn::session()->end();

            }

        } catch  (\Exception $e) {
           self::log('Ending session', ['Error' => $e.getMessage]);
        }

        // Start the 'session' as Guests
        if (!Gdn::session()->isValid()) {
           self::log('Starting a session as guest', []);
            Gdn::session()->start(false, false);
        }

    }

    public function entryController_topcoder_create($sender, $action = '', $errorCode = '') {
       self::log('entryController_topcoder_create:', ['action' => $action ]);
        if($errorCode && $action=='signin') {
            $sender->SelfUrl = '';
            $sender->setData('Title', 'Error');
            $sender->setData('Error', self::ERROR_CODES[$errorCode]);
            $sender->render('index', 'entry', 'plugins/topcoder');
        } else {
            redirectTo('/entry/signin?Target=discussions', 302);
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
     * Refresh a token from an identity service
     * @return |null
     */
    public function getRefreshToken($token)  {
        $TOPCODER_AUTH0_AUTH_URL = c('Plugins.Topcoder.SSO.Auth0Domain').c('Plugins.Topcoder.SSO.AuthorizationURI');
        $options = array('http' => array(
            'method' => 'GET',
            'header' => 'Authorization: Bearer '.$token
        ));

        $context = stream_context_create($options);
        try {
            $data = file_get_contents($TOPCODER_AUTH0_AUTH_URL, false, $context);
            if($data !== false) {
                $response = json_decode($data);
                return $response->result->content->refreshToken;
            }
        } catch (Exception $e) {
           self::log('Couldn\'t refresh a token', ['Error' => $e->getMessage()]);
        }

        return null;
    }

    /**
     * Extra styling on the discussion view.
     *
     * @param \Vanilla\Web\Asset\LegacyAssetModel $sender
     */
    public function assetModel_styleCss_handler($sender) {
        $sender->addCssFile('topcoder.css', 'plugins/Topcoder');
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
    /** **/
    /**
     * Add scripts. Add script to hide iPhone browser bar on pageload.
     */
    public function base_render_before($sender) {
        if (is_object($sender->Head)) {
            $sender->Head->addString($this->getJS());
        }

        if($sender instanceof DiscussionController || $sender instanceof GroupController) {
            if($sender->data('Group')) {
                $Group = $sender->data('Group');
                $challengeID = $Group->ChallengeID;
                if($challengeID) {
                    $resources = $this->getChallengeResources($challengeID);
                    $roleResources = $this->getRoleResources();
                    $sender->setData('Resources', $resources);
                    $sender->setData('RoleResources', $roleResources);

                }
            }
        }
    }

    /**
     * Add a topcoder role type in Dashboard
     * @param $sender
     * @param $args
     */
    public function roleController_render_before($sender, $args) {
        $types = $sender->data('_Types');
        if($types) {
            $types['topcoder'] = self::ROLE_TYPE_TOPCODER;
            $sender->SetData('_Types', $types);
        }
    }

    /**
     * Allows user to mark a category.
     * Override the Vanilla method to stay in the same page
     *
     * @param $categoryID
     * @param $tKey
     */
     public function categoryController_markRead_create($categoryID, $tKey) {
        $categoryModel = new CategoryModel();
        if (Gdn::session()->validateTransientKey($tKey)) {
            $categoryModel->saveUserTree($categoryID, ['DateMarkedRead' => Gdn_Format::toDateTime()]);
        }

        // Stay in the previous page
        if(isset($_SERVER['HTTP_REFERER'])) {
            $previous = $_SERVER['HTTP_REFERER'];
            redirectTo($previous);
        } else {
            redirectTo('/categories');
        }

    }

    /**
     * Allows user to follow or unfollow a category.
     * Override the Vanilla method to stay in the same page
     *
     * @param null $categoryID
     * @param null $tKey
     * @throws Gdn_UserException
     */
    public function categoryController_followed_create($sender,$categoryID = null, $tKey = null) {
        // Make sure we are posting back.
       if (!$sender->Request->isAuthenticatedPostBack() && !Gdn::session()->validateTransientKey($tKey)) {
            throw permissionException('Javascript');
        }

        if (!Gdn::session()->isValid()) {
            throw permissionException('SignedIn');
        }

        $userID = Gdn::session()->UserID;

        $categoryModel = new CategoryModel();
        $category = CategoryModel::categories($categoryID);
        if (!$category) {
            throw notFoundException('Category');
        }

        // Check the form to see if the data was posted.
        $form = new Gdn_Form();
        $categoryID = $form->getFormValue('CategoryID', $categoryID);
        $followed = $form->getFormValue('Followed', null);
        $hasPermission = $categoryModel::checkPermission($categoryID, 'Vanilla.Discussions.View');
        if (!$hasPermission) {
            throw permissionException('Vanilla.Discussion.View');
        }
        $result = $categoryModel->follow($userID, $categoryID, $followed);

        // Set the new value for api calls and json targets.
        $sender->setData([
            'UserID' => $userID,
            'CategoryID' => $categoryID,
            'Followed' => $result
        ]);

        switch ($sender->deliveryType()) {
            case DELIVERY_TYPE_DATA:
                $sender->render('Blank', 'Utility', 'Dashboard');
                return;
            case DELIVERY_TYPE_ALL:
                // Stay in the previous page
                if(isset($_SERVER['HTTP_REFERER'])) {
                    $previous = $_SERVER['HTTP_REFERER'];
                    redirectTo($previous);
                } else {
                    redirectTo('/categories');
                }
        }

        // Return the appropriate bookmark.
        require_once $sender->fetchViewLocation('helper_functions', 'Categories');
        $markup = followButton($categoryID);
        $sender->jsonTarget("!element", $markup, 'ReplaceWith');

        $sender->render('Blank', 'Utility', 'Dashboard');
    }

    /**
     * Silently Token Refresh Logic for JWT RS256
     * @return string
     */
    private function getJS() {
        $url= c('Plugins.Topcoder.SSO.RefreshTokenURL');
        $jsString = '<script>function prepareFrame() {'.
            'var ifrm = document.createElement("iframe");'.
            'ifrm.setAttribute("src", "'.$url.'");'.
            'ifrm.style.width = "0px"; ifrm.style.height = "0px";'.
            'document.body.appendChild(ifrm);}'.
            'window.onload = prepareFrame;</script>';
        return $jsString;
    }

    /**
     * Generated a random string
     * @param int $length
     * @return string
     */
    private function getRandomString($length = 8) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $string = '';

        for ($i = 0; $i < $length; $i++) {
            $string .= $characters[mt_rand(0, strlen($characters) - 1)];
        }

        return $string;
    }

    /** ------------------- Export Data Related Methods --------------------- */

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

    /** ------------------- Topcoder Profile and UI customization Related Methods --------------------- */

    /**
     * Use a Topcoder Photo on the user' profile.
     * Add Topcoder Links in/from a sided menu.
     * Remove Edit profile link
     * Remove Password links
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
        $sideMenu->removeLink('Options', sprite('SpPassword').' '.t('Change My Password'));
        $sideMenu->removeLink('Options', sprite('SpPassword').' '.t('Set A Password'));
        $sideMenu->removeLink('Options', sprite('SpEdit').' '.t('Edit Profile'));
    }

    /**
     * Remove Edit profile links from Profile Drorpdown Options
     *
     * @param $sender
     * @param $args
     */
    public function profileController_beforeProfileOptions_handler($sender, $args) {
        $sideMenu = $sender->EventArguments['ProfileOptionsDropdown'];
        $sideMenu->removeItem('edit-profile');
    }

    /**
     * Don't show Edit Profile
     * @param $sender
     * @param $args
     */
    public function profileController_edit_create($sender, $args) {
       self::log('profileController_edit_handler', []);
        redirectTo('/profile');
    }

    /**
     * Don't show Change Password
     * @param $sender
     * @param $args
     */
    public function profileController_password_create($sender, $args) {
       self::log('profileController_edit_handler', []);
        redirectTo('/profile');
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
        $TOPCODER_AUTH0_CLIENT_ID = c('Plugins.Topcoder.M2M.Auth0ClientId');
        $TOPCODER_AUTH0_CLIENT_SECRET = c('Plugins.Topcoder.M2M.Auth0ClientSecret');
        $TOPCODER_AUTH0_AUDIENCE = c('Plugins.Topcoder.M2M.Auth0Audience');
        $TOPCODER_AUTH0_URL =  c('Plugins.Topcoder.M2M.Auth0Url');
        $TOPCODER_AUTH0_PROXY_SERVER_URL =  c('Plugins.Topcoder.M2M.Auth0ProxyServerUrl');

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
     * Get a list of Topcoder Resource roles
     * @return mixed|null
     */
    public function getRoleResources() {
        $token = TopcoderPlugin::getM2MToken();
        if ($token) {
            $resourceRolesURI = c('Plugins.Topcoder.ResourceRolesApiURI');
            $topcoderRolesApiUrl = c('Plugins.Topcoder.BaseApiURL') . $resourceRolesURI;
            $options = array('http' => array(
                'method' => 'GET',
                'header' => 'Authorization: Bearer ' .$token
            ));
            $context = stream_context_create($options);
            $resourceData = file_get_contents($topcoderRolesApiUrl , false, $context);
            if ($resourceData === false) {
                // Handle errors (e.g. 404 and others)
               self::log('Couldn\'t get Topcoder Role Resources', ['headers' =>json_encode($http_response_header)]);
                logMessage(__FILE__, __LINE__, 'TopcoderPlugin', 'getRoleResources',
                    "Couldn't get Topcoder Role Resources".json_encode($http_response_header));
                return null;
            }

            return json_decode($resourceData);
        }
       self::log('Couldn\'t get Topcoder Role Resources: no token', []);
       return null;
    }

    /**
     * Get Topcoder Challenge Resources
     * @param $challengeId
     * @return mixed|null
     */
    public function getChallengeResources($challengeId) {
        $token = TopcoderPlugin::getM2MToken();
        if ($token) {
            $resourcesURI = c('Plugins.Topcoder.ResourcesApiURI');
            $topcoderRolesApiUrl = c('Plugins.Topcoder.BaseApiURL') . $resourcesURI;
            $options = array('http' => array(
                'method' => 'GET',
                'header' => 'Authorization: Bearer ' .$token
            ));
            $context = stream_context_create($options);
            $resourceData = file_get_contents($topcoderRolesApiUrl . '?challengeId=' . $challengeId, false, $context);
            if ($resourceData === false) {
                // Handle errors (e.g. 404 and others)
               self::log('Couldn\'t get challenge resources: no token', ['headers'=> json_encode($http_response_header)]);
                logMessage(__FILE__, __LINE__, 'TopcoderPlugin', 'getChallengeResources', "Couldn't get Topcoder challenge resources".json_encode($http_response_header));
                return null;
            }

            return json_decode($resourceData);
        }
        self::log('Couldn\'t get challenge resources: no token', []);
        return null;
    }

    /**
     * Get a Topcoder Roles
     *
     * @param $name Topcoder Handle
     * @return null|string  array of role objects. Example of role object:
     *  {
     *       "id":"3",
     *       "modifiedBy":null,
     *       "modifiedAt":null,
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
                    return false;
                }

                $rolesResponse = json_decode($rolesData);
                if ($rolesResponse->result->status === 200 && $rolesResponse->result->content !== null) {
                    return $rolesResponse->result->content;
                }
            }
        }
        return false;
    }

    /**
     * Get all Topcoder Roles
     *
     * @return null|string  array of role objects. Example of role object:
     *  {
     *       "id":"3",
     *       "modifiedBy":null,
     *       "modifiedAt":null,
     *       "createdBy":null,
     *       "createdAt":null,
     *       "roleName":"Connect Support"
     *   }
     */
    public static function getAllTopcoderRoles() {
        $token = TopcoderPlugin::getM2MToken();
        if ($token) {
            $topcoderRolesApiUrl = c('Plugins.Topcoder.BaseApiURL') . c('Plugins.Topcoder.RoleApiURI');
            $options = array('http' => array(
                'method' => 'GET',
                'header' => 'Authorization: Bearer ' .$token
            ));
            $context = stream_context_create($options);
            $rolesData = file_get_contents($topcoderRolesApiUrl, false, $context);
            if ($rolesData === false) {
                // Handle errors (e.g. 404 and others)
                logMessage(__FILE__, __LINE__, 'TopcoderPlugin', 'getAllTopcoderRoles', "Couldn't get all Topcoder roles".json_encode($http_response_header));
                return null;
            }

            $rolesResponse = json_decode($rolesData);
            if ($rolesResponse->result->status === 200 && $rolesResponse->result->content !== null) {
                return $rolesResponse->result->content;
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
            return false;
        }
        $memberStatsResponse = json_decode($memberStatsData);
        if($memberStatsResponse->result->status === 200 && $memberStatsResponse->result->content[0]) {
            return $memberStatsResponse->result->content[0]->maxRating != null ?
                $memberStatsResponse->result->content[0]->maxRating->rating : null;
        }

        return false;
    }

    /**
     * Get css style based on Topcoder Member Rating
     * @param $rating It might be null
     * @return mixed|string
     */
    public static function getRatingCssClass($rating){
        $cssStyle = '';
        if($rating == null) {
            $cssStyle = 'coderRatingNone';
        } else if ($rating >= 0 && $rating < 900) {
            $cssStyle = 'coderRatingGrey';
        } else if ($rating > 899 && $rating < 1200) {
            $cssStyle = 'coderRatingGreen';
        } else if ($rating > 1199 && $rating < 1500) {
            $cssStyle = 'coderRatingBlue';
        } else if ($rating > 1499 && $rating < 2200) {
            $cssStyle = 'coderRatingYellow';
        } else if ($rating > 2199) {
            $cssStyle ='coderRatingRed';
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


    // TODO: Debugging issues-108
    public function base_beforeNewDiscussionButton_handler($sender, $args) {
       $newDiscussionModule = $args['NewDiscussionModule'];
       self::log('NewDiscussionModule_beforeNewDiscussionButton_handler', [
            'ShowGuests' => $newDiscussionModule->ShowGuests,
            'CategoryID' => $newDiscussionModule->CategoryID, 'session.isValid' => Gdn::session()->isValid(),
            'privilegedGuest' => ($newDiscussionModule->ShowGuests && !Gdn::session()->isValid()),
            'hasPermission' => Gdn::session()->checkPermission('Vanilla.Discussions.Add', true, 'Category', 'any')]);

    }

    // TODO: Debugging issues-108
    public function gdn_dispatcher_beforeDispatch_handler($sender, $args) {
        self::log('gdn_dispatcher_beforeDispatch_handler', [
            'Permissions' => Gdn::session()->getPermissionsArray(),
        ]);
    }

    // TODO: Debugging issues-108
    public function userModel_loadPermissions_handler($sender, $args){
        self::log('userModel_loadPermissions_handler', ['user' => $args['UserID'],
            'loadPermissions' => $args['Permissions']]);
    }

    // TODO: Debugging search
    public function searchModel_search_handler($sender, $args){
        self::log('searchModel_search_handler', ['Search' => $args['Search']]);
    }

    // TODO: Debugging search
    public function searchModel_beforeGetSearchQuery_handler($sender, $args){
        self::log('searchModel_beforeGetSearchQuery_handler', ['Sql' => $args['Sql'],
            'Parameters' => $args['Parameters']]);
    }

    // TODO: Debugging search
    public function searchController_beforeSearchExcerpt_handler($sender, $args){
        self::log('searchController_beforeSearchExcerpt_handler', ['Record' => $args['Record']
         ]);
    }

    public static function log($message, $data = []) {
        // TODO: Debugging issues-108
        //if (c('Vanilla.SSO.Debug') || c('Debug')) {
            Logger::event(
                'topcoder_plugin',
                Logger::INFO,
                $message,
                $data
            );
       // }
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
        return TopcoderPlugin::getRatingCssClass($topcoderRating);
    }
}

if(!function_exists('topcoderRoleCssStyles')) {
    /**
     * Take an user name to get role css style .
     *
     * @return string Returns role css style
     */
    function topcoderRoleCssStyles($name) {
        $topcoderCssClass = '';
        $isTopcoderAdmin = TopcoderPlugin::hasTopcoderAdminRole($name);
        if($isTopcoderAdmin) {
            $topcoderCssClass = ' '.'topcoderAdmin' ;
        }
        return $topcoderCssClass;
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

        Gdn::controller()->EventArguments['User'] = $user;
        Gdn::controller()->EventArguments['Title'] =& $title;
        Gdn::controller()->EventArguments['Attributes'] =& $attributes;
        Gdn::controller()->fireEvent('UserPhoto');

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
        if($topcoderRating != false || $topcoderRating == null) {
            $coderStyles = TopcoderPlugin::getRatingCssClass($topcoderRating);
            $attributes['class'] = $attributes['class'].' '.$coderStyles ;
        }

        $isTopcoderAdmin = TopcoderPlugin::hasTopcoderAdminRole($name);
        if($isTopcoderAdmin) {
            $attributes['class'] = $attributes['class'].' '. 'topcoderAdmin' ;
        }

        Gdn::controller()->EventArguments['User'] = $user;
        Gdn::controller()->EventArguments['Text'] =& $text;
        Gdn::controller()->EventArguments['Attributes'] =& $attributes;
        Gdn::controller()->fireEvent('UserAnchor');

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
