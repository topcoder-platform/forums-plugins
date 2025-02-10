<?php

class DebugPlugin extends Gdn_Plugin {

    public function __construct() {
        parent::__construct();
    }

    /**
     * Run once on enable.
     *
     */
    public function setup() {
        if(!c('Garden.Installed')) {
            return;
        }
    }

}
