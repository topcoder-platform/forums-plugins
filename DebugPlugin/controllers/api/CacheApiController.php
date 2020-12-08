<?php

use Garden\Web\Exception\ClientException;
use Garden\Schema\Schema;
use Vanilla\Utility\InstanceValidatorSchema;
use Garden\Web\Data;
use Garden\Web\Exception\NotFoundException;
use Garden\Web\Exception\ServerException;
use Vanilla\ApiUtils;

/**
 * Cache API Controller for the `/cache` resource.
 */
class CacheApiController extends AbstractApiController {


    /**
     * Retrieve a key's value from the cache
     * @param array $query a cache key
     * @return mixed
     */
    public function index(array $query) {
        $this->permission('Garden.Settings.Manage');

        $in = $this->schema([
            'key:s' => 'Cache key'
        ], 'in')->setDescription('Get a value from Cache');

        $query = $in->validate($query);
        $key = $query['key'];

        if(Gdn_Cache::activeCache()) {
            if(Gdn::cache()->exists($key) !== false) {
                $value = Gdn::cache()->get($key);
                if ($value === Gdn_Cache::CACHEOP_FAILURE) {
                    return false;
                } else if (is_array($value)) {
                    return json_encode($value);
                } else if (is_object($value)) {
                    return json_encode((array)$value);
                } else {
                    return $value;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Invalidate all items in the cache
     * @return bool <b>TRUE</b> on success or <b>FALSE</b> on failure.
     */
    public function get_flush() {
        $this->permission('Garden.Settings.Manage');

        if(Gdn_Cache::activeCache()) {
            return json_encode(Gdn::cache()->flush());
        } else {
            return false;
        }
    }
}