<?php

use Garden\Web\Exception\ClientException;
use Garden\Schema\Schema;
use Vanilla\Utility\InstanceValidatorSchema;
use Garden\Web\Data;
use Garden\Web\Exception\NotFoundException;
use Garden\Web\Exception\ServerException;
use Vanilla\ApiUtils;

/**
 * SQL API Controller for the `/sql` resource.
 */
class SqlApiController extends AbstractApiController {

    /**
     *      *
     * @param array $query The query string.
     * @return Data
     */
    public function index(array $query) {
        $this->permission('Garden.Settings.Manage');

        $in = $this->schema([
            'sql:s' => 'Sql query'
        ], 'in')->setDescription('Get a list of records.');

        $query = $in->validate($query);
        $sql = $query['sql'];

        if (strpos(strtolower($sql), 'select') !== 0) {
            throw new ClientException('Unable to execute this query.');
        }

        $data = Gdn::sql()->query($sql, 'select')->resultArray();
        return $data;
    }
}