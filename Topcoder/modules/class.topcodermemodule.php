<?php
/**
 * Topcoder Me module.
 */

/**
 * Selfish bastard.
 */
class TopcoderMeModule extends Gdn_Module {

    /** @var string  */
    public $CssClass = '';

    public function __construct() {
        parent::__construct();
        $this->_ApplicationFolder = 'plugins/topcoder';
    }

    public function assetTarget() {
        return 'Panel';
    }
}
