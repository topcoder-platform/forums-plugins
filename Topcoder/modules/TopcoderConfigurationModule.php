<?php
/**
 * Topcoder Configuration module.
 *
 */

/**
 * This class gives a simple way to load/save Topcoder plugin configuration settings.
 * To use this module you must:
 *  1. Call schema() to set the config fields you are using.
 *  2. Call initialize() within the controller to load/save the data.
 *  3. Do one of the following:
 *   a) Call the controller's render() method and call render() somewhere inside of the view.
 *   b) Call this object's renderAll() method within the view if you don't want to customize the view any further.
 */
class TopcoderConfigurationModule extends ConfigurationModule{

    /**
     *
     *
     * @param Gdn_Controller $Controller The controller using this model.
     */
    public function __construct($sender = null) {
        parent::__construct($sender);
    }

    /**
     * Set the data definition to load/save from the config.
     *
     * @param array $def A list of fields from the config that this form will use.
     */
    public function schema($def = null) {
        if ($def !== null) {
            $schema = [];

            foreach ($def as $key => $value) {
                $row = ['Name' => '', 'Type' => 'string', 'Control' => 'TextBox', 'Options' => []];

                if (is_numeric($key)) {
                    $row['Name'] = $value;
                } elseif (is_string($value)) {
                    $row['Name'] = $key;
                    $row['Type'] = $value;
                } elseif (is_array($value)) {
                    $row['Name'] = $key;
                    $row = array_merge($row, $value);
                } else {
                    $row['Name'] = $key;
                }
                if(strpos($row['Name'], 'AuthenticationProvider') === 0) {
                    touchValue('AuthenticationProvider', $row, substr($row['Name'], strlen('AuthenticationProvider.')));
                } else {
                    touchValue('Config', $row, $row['Name']);
                }
                $schema[] = $row;
            }
            $this->_Schema = $schema;
        }
        return $this->_Schema;
    }
    /**
     *
     *
     * @param null $schema
     * @throws Exception
     */
    public function initialize($schema = null) {
        if ($schema !== null) {
            $this->schema($schema);
        }

        /** @var Gdn_Form $Form */
        $form = $this->form();

        if ($form->authenticatedPostBack()) {
            // Grab the data from the form.
            $configData = [];
            $authenticationProviderData = [];
            $post = $form->formValues();

            foreach ($this->_Schema as $row) {
                $name = $row['Name'];

                // For API calls make this a sparse save.
                if ($this->controller()->deliveryType() === DELIVERY_TYPE_DATA && !array_key_exists($name, $post)) {
                    continue;
                }

                if (strtolower(val('Control', $row)) == 'imageupload') {
                    $options = arrayTranslate($row, ['Prefix', 'Size']);
                    if (val('OutputType', $row, false)) {
                        $options['OutputType'] = val('OutputType', $row);
                    }
                    if (val('Crop', $row, false)) {
                        $options['Crop'] = val('Crop', $row);
                    }

                    // Old image to clean!
                    $options['CurrentImage'] = c($name, false);

                    // Save the new image and clean up the old one.
                    $form->saveImage($name, $options);
                }

                $value = $form->getFormValue($name);

                // Trim all incoming values by default.
                if (val('Trim', $row, true)) {
                    $value = trim($value);
                }

                if ($value == val('Default', $value, '')) {
                    $value = '';
                }

                if(array_key_exists('Config', $row)) {
                    $config = $row['Config'];
                    $configData[$config] = $value;
                } else if(array_key_exists('AuthenticationProvider', $row)) {
                    $authenticationProvider = $row['AuthenticationProvider'];
                    $authenticationProviderData[$authenticationProvider] = $value;
                }

                $this->controller()->setData($name, $value);
            }

            // Halt the save if we've had errors assigned.
            if ($form->errorCount() == 0) {
                // Save it to the config.
                saveToConfig($configData, ['RemoveEmpty' => true]);

                $model = new Gdn_AuthenticationProviderModel();
                $authform = new Gdn_Form();
                $authform->setModel($model);
                $authform->setFormValue('AuthenticationKey','topcoder');
                $authform->setFormValue('SignInUrl' , $authenticationProviderData['SignInUrl']);
                $authform->setFormValue('SignOutUrl' , $authenticationProviderData['SignOutUrl']);
                $authform->setFormValue('Attributes' , '');
                if($authform->save()) {
                    $this->_Sender->informMessage(t('Saved'));
                } else {
                    $this->_Sender->errorMessage('Couldn\'t save Authentication Provider');
                }

            }
        } else {
            // Load the form data from the config.
            $provider = Gdn_AuthenticationProviderModel::getProviderByKey('topcoder');
            $data = [];
            foreach ($this->_Schema as $row) {

                if(strpos($row['Name'], 'AuthenticationProvider') === 0) {
                    $data[$row['Name']] = $provider[$row['AuthenticationProvider']];
                } else {
                    $data[$row['Name']] = c($row['Config'], val('Default', $row, ''));
                }
            }
            $this->log('loading', ['data' => $data, 'provider' =>$provider]);
            $form->setData($data);
            $this->controller()->Data = array_merge($this->controller()->Data, $data);
            $this->log('merging', ['data' => $this->controller()->Data]);
        }
    }

    /**
     *
     *
     * @throws Exception
     */
    public function renderAll() {
        $this->RenderAll = true;
        $controller = $this->controller();
        $controller->ConfigurationModule = $this;

        $controller->render($this->fetchViewLocation('configuration','dashboard'));
        $this->RenderAll = false;
    }

    public function log($message, $data) {
        if (c('Vanilla.SSO.Debug')) {
            Logger::event(
                'logging',
                Logger::INFO,
                $message,
                $data
            );
        }
    }

}