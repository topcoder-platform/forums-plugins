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

    public function get_extendedstats(array $query) {
        $this->permission('Garden.Settings.Manage');
        $in = $this->schema([
            'type:s' => 'The type of statistics to fetch(stats, detail, cachedump, slabs, items, sizes)',
            'slabid:i?' => 'Slab ID',
            'limit:i?' => 'Limit the number of entries to dump'
        ], 'in')->setDescription('Get server statistics');

        $query = $in->validate($query);
        $type = $query['type'];
        $slabID = $query['slabid'];
        $limit = $query['limit'];

        if(Gdn_Cache::activeCache()) {
            $pos = strrpos(getenv('MEMCACHED_SERVER'), ':');
            $server = substr(getenv('MEMCACHED_SERVER'), 0, $pos);
            $port = substr(getenv('MEMCACHED_SERVER'), $pos+1);
            switch ($type) {
                case 'slabs':
                    return $this->sendMemcacheCommand($server, $port,'stats slabs');
                case 'stats':
                    return $this->sendMemcacheCommand($server, $port,'stats');
                case 'items':
                    return $this->sendMemcacheCommand($server, $port,'stats items');
                case 'sizes':
                    return $this->sendMemcacheCommand($server, $port,'stats sizes');
                case 'detail_on':
                    return $this->sendMemcacheCommand($server, $port,'stats detail on');
                case 'detail_off':
                    return $this->sendMemcacheCommand($server, $port,'stats detail off');
                case 'detail_dump':
                    return $this->sendMemcacheCommand($server, $port,'stats detail dump');
                case 'cachedump':
                    if(!$slabID) {
                        return 'Missing slabid';
                    }
                    $limit = isset($limit)? $limit:100;
                    return  $this->sendMemcacheCommand($server, $port,'stats cachedump '.$slabID.' '.$limit);
                default:
                    return 'Not supported';
            }
        } else {
            return 'Cached disabled';
        }
    }

    function sendMemcacheCommand($server,$port,$command){

        $s = @fsockopen($server,$port);
        if (!$s){
            die("Cant connect to:".$server.':'.$port);
        }

        fwrite($s, $command."\r\n");

        $buf='';
        while ((!feof($s))) {
            $buf .= fgets($s, 256);
            if (strpos($buf,"END\r\n")!==false){ // stat says end
                break;
            }
            if (strpos($buf,"DELETED\r\n")!==false || strpos($buf,"NOT_FOUND\r\n")!==false){ // delete says these
                break;
            }
            if (strpos($buf,"OK\r\n")!==false){
                break;
            }
            if (strpos($buf,"ERROR\r\n")!==false){
                break;
            }
        }
        fclose($s);
        return $buf;
    }
}