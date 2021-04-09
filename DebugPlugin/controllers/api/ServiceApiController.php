<?php

use Garden\Web\Exception\ClientException;
use Garden\Schema\Schema;
use Vanilla\Utility\InstanceValidatorSchema;
use Garden\Web\Data;
use Garden\Web\Exception\NotFoundException;
use Garden\Web\Exception\ServerException;
use Vanilla\ApiUtils;

/**
 * SQL API Controller for the `/service` resource.
 */
class ServiceApiController extends AbstractApiController {
    /**
     *
     * @param array $query The query string.
     * @return Data
     */
    public function get_tidewayslog($path='/var/log/tideways/daemon.log') {
        $this->permission('Garden.Settings.Manage');

        if (file_exists($path)) {
            //Get file type and set it as Content Type
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            header('Content-Type: ' . finfo_file($finfo, $path));
            finfo_close($finfo);

            header('Content-Description: File Transfer');
            header('Content-Disposition: attachment; filename='.basename($path));
            header('Expires: 0');
            header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
            header('Pragma: public');
            header('Content-Length: ' . filesize($path));
            ob_clean();
            flush();
            readfile($path);
            exit;
        } else {
            throw notFoundException('File');
        }
    }

}