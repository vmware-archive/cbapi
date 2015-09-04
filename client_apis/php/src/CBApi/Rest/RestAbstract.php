<?php

namespace CBApi\Rest;

use CBApi\Connection\Request;

/**
 * Class RestAbstract
 * @package CBApi\Rest
 */
abstract class RestAbstract
{
    /** @var Request */
    protected $request;

    /**
     * @param Request $request
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * @param $query
     * @param $start
     * @param $rows
     * @param $sort
     * @param $facet
     * @return array
     */
    protected function getBaseSearch($query, $start, $rows, $sort, $facet)
    {
        $search = array(
            'start'     => $start,
            'rows'      => $rows,
            'sort'      => $sort,
            'facet'     => array($facet, $facet),
            'cb.urlver' => 1
        );

        if ($query !== '') {
            $search['q'] = $query;
        }

        return $search;
    }

    /**
     * @param $group_id
     * @return array
     */
    protected function getSensorMapping($group_id)
    {
        return Sensors::getSensorMapping($group_id);
    }
}
