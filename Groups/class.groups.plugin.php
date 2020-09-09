<?php
/**
 * Class GroupsPlugin
 */

use Garden\Container\Reference;
use Garden\Schema\Schema;
use Garden\Web\Exception\ClientException;
use Vanilla\ApiUtils;
use Garden\Container\Container;


class GroupsPlugin extends Gdn_Plugin {
    const GROUPS_ROUTE = 'groups';

    /**
     * Run once on enable.
     */
    public function setup() {
        $this->structure();
    }
    /**
     * OnDisable is run whenever plugin is disabled.
     *
     * We have to delete our internal route because our custom page will not be
     * accessible any more.
     *
     * @return void.
     */
    public function onDisable() {
        // nothing
    }

    public function base_render_before($sender) {
        $sender->addJsFile('vendors/prettify/prettify.js', 'plugins/Groups');
        $sender->addJsFile('dashboard.js', 'plugins/Groups');
    }
    /**
     * Load CSS into head for the plugin
     * @param $sender
     */
    public function assetModel_styleCss_handler($sender) {
        $sender->addCssFile('groups.css', 'plugins/Groups');
    }

    /**
     * The settings page for the topcoder plugin.
     *
     * @param Gdn_Controller $sender
     */
    public function settingsController_groups_create($sender) {
        $cf = new ConfigurationModule($sender);
        $cf->initialize([
            'Vanilla.Groups.PerPage' => ['Control' => 'TextBox', 'Default' => '30', 'Description' => 'Groups per a page'],
        ]);

        $sender->setData('Title', sprintf(t('%s Settings'), 'Groups'));
        $cf->renderAll();
    }

    public function discussionsController_afterDiscussionFilters_handler($sender){
        echo '<li>'. anchor('Groups', '/groups').'</li>';
    }
    /**
     * Database updates.
     */
    public function structure() {
        include __DIR__.'/structure.php';
    }
}

