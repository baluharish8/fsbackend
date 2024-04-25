const adminData = require('../models/admindata')
const googleAdmin = require('../models/googleadmin')
const VendorData = require('../models/mvmodels')
const ServiceData = require('../models/vendorservicesdata')
const crypto = require("crypto"); // for data encryption
const bcrypt = require('bcryptjs'); // for password hashing
const nodemailer = require("nodemailer");
const jwt = require('jsonwebtoken');
const { SearchQuery, Click, View, Session } = require('../models/analyticsdb')



    const search= async (req, res) => {

    const query = req.body.query; // Get search query from request body
    console.log(req.body.query)
    try {
        // Log the search query to MongoDB
        await SearchQuery.create({ query });

        // Return search results to the user
        res.sendStatus(200);

    } catch (error) {
        console.error('Error logging search query:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const getsearchcount= async (req, res) => {

    try {
        const activeUsersCount = await SearchQuery.countDocuments({});
        //   console.log(activeUsersCount, 'from active users count')
        res.json(activeUsersCount);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const popularSearches= async (req, res) => {

    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await SearchQuery.aggregate([
            { $group: { _id: '$query', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);

        res.json(popularItems);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const click= async (req, res) => {

    const { itemId } = req.body; // Get ID of the clicked item

    try {
        // Log the click event to MongoDB
        await Click.create({ itemId });
        res.sendStatus(200);
    } catch (error) {
        console.error('Error logging click event:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}

    const getclickcount= async (req, res) => {

    try {
        const activeUsersCount = await Click.countDocuments({});
        //   console.log(activeUsersCount, 'from active users count')
        res.json(activeUsersCount);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const popularClicks= async (req, res) => {

    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await Click.aggregate([
            { $group: { _id: '$itemId', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // Fetch all documents corresponding to the IDs
        let data = await ServiceData.find({ _id: { $in: ids } });
        // console.log(data.length, 'click ids data')

        const mergedClicksData = [];
        for (let i = 0; i < popularItems.length; i++) {
            const popularItemId = popularItems[i]._id;
            console.log(popularItemId, 'popularItemId')
            const count = popularItems[i].count;
            // console.log(data[i].id, 'servicesids')

            const matchingDataItem = data.find(item => item.id === popularItemId);

            if (matchingDataItem) {
                const item = {
                    _id: popularItemId,
                    count: count,
                    name: matchingDataItem.name // Additional data from data array matching the ID
                };

                mergedClicksData.push(item);
            } else {
                console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
            }
        }

        // console.log(mergedData,'mergedData')
        res.json(mergedClicksData);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}

    const vendorPopularClicks= async (req, res) => {

    const { _id } = req.body
    console.log('from vendoritemcllicks vendorId', _id)
    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await Click.aggregate([
            { $group: { _id: '$itemId', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // Fetch all documents corresponding to the IDs
        let data = await ServiceData.find({ _id: { $in: ids } });
        // console.log(data[1].category,data[1].vendorId, 'click ids data')
        console.log(data.length, 'from service data length')
        // const filteredItems = data.filter(item => console.log(item.category,item.vendorId,item.name));

        const mergedClicksData = [];
        for (let i = 0; i < popularItems.length; i++) {
            const popularItemId = popularItems[i]._id;
            // console.log(popularItemId, 'popularItemId')
            const count = popularItems[i].count;
            // console.log(data, 'servicesids')

            const matchingDataItem = data.find(item => item.id === popularItemId);

            if (matchingDataItem) {
                const item = {
                    _id: popularItemId,
                    count: count,
                    name: matchingDataItem.name, // Additional data from data array matching the ID
                    vendorId: matchingDataItem.vendorId
                };

                mergedClicksData.push(item);
            } else {
                console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
            }
        }


        const filteredVendoritemClicks = mergedClicksData.filter(item => item.vendorId === _id);


        console.log(filteredVendoritemClicks, 'filteredVendoritemClicks')

        res.json(filteredVendoritemClicks);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const view= async (req, res) => {

    const { itemId, category } = req.body; // Get ID of the viewed item

    try {
        // Log the view event to MongoDB
        await View.create({ itemId, categories: category });
        res.sendStatus(200);
    } catch (error) {
        console.error('Error logging view event:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const getviewcount= async (req, res) => {

    try {
        const activeUsersCount = await View.countDocuments({});
        //   console.log(activeUsersCount, 'from active users count')
        res.json(activeUsersCount);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const popularViews= async (req, res) => {

    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await View.aggregate([
            { $group: { _id: '$itemId', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // Fetch all documents corresponding to the IDs
        let data = await ServiceData.find({ _id: { $in: ids } });
        // console.log(data.length, 'click ids data')

        const mergedClicksData = [];
        for (let i = 0; i < popularItems.length; i++) {
            const popularItemId = popularItems[i]._id;
            console.log(popularItemId, 'popularItemId')
            const count = popularItems[i].count;
            // console.log(data[i].id, 'servicesids')

            const matchingDataItem = data.find(item => item.id === popularItemId);

            if (matchingDataItem) {
                const item = {
                    _id: popularItemId,
                    count: count,
                    name: matchingDataItem.name, // Additional data from data array matching the ID

                };

                mergedClicksData.push(item);
            } else {
                console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
            }
        }
        // console.log(mergedData,'mergedData')
        res.json(mergedClicksData);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const vendorPopularViews= async (req, res) => {

    const { _id } = req.body

    try {
        // Perform aggregation to get the count of clicks for each unique item ID
        const popularItems = await View.aggregate([
            { $group: { _id: '$itemId', count: { $sum: 1 } } }, // Group by item ID and count clicks
            { $sort: { count: -1 } } // Sort by count in descending order
        ]);
        const ids = popularItems.map(item => item._id); // Assuming popularItems is your array of IDs

        // Fetch all documents corresponding to the IDs
        let data = await ServiceData.find({ _id: { $in: ids } });
        // console.log(data.length, 'click ids data')

        const mergedClicksData = [];
        for (let i = 0; i < popularItems.length; i++) {
            const popularItemId = popularItems[i]._id;
            // console.log(popularItemId, 'popularItemId')
            const count = popularItems[i].count;
            // console.log(data[i].id, 'servicesids')

            const matchingDataItem = data.find(item => item.id === popularItemId);

            if (matchingDataItem) {
                const item = {
                    _id: popularItemId,
                    count: count,
                    name: matchingDataItem.name, // Additional data from data array matching the ID
                    vendorId: matchingDataItem.vendorId

                };

                mergedClicksData.push(item);
            } else {
                console.warn(`No matching data found for popular item with ID: ${popularItemId}`);
            }
        }
        const filteredVendoritemViews = mergedClicksData.filter(item => item.vendorId === _id);

        // console.log(mergedData,'mergedData')
        console.log(filteredVendoritemViews, 'filteredVendoritemViews')

        res.json(filteredVendoritemViews);
    } catch (error) {
        console.error('Error fetching popular items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const popularCategories= async (req, res) => {

    try {
        // Perform aggregation to get the most popular categories
        const popularCategories = await View.aggregate([
            { $group: { _id: '$categories', count: { $sum: 1 } } }, // Group by categories
            { $sort: { count: -1 } }, // Sort by count in descending order
            { $limit: 10 } // Limit to top 10 categories
        ]);

        res.json(popularCategories);
    } catch (error) {
        console.error('Error fetching popular categories:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const sendsessionduration= async (req, res) => {

    const { duration, _id } = req.body; // Get ID of the viewed item

    try {
        // Log the view event to MongoDB
        let data = await Session.create({ duration });
        if (data) {
            await VendorData.findByIdAndUpdate(_id, { lastActivity: Date.now() - 2 * 60 * 1000 });

        }
        res.sendStatus(200);
    } catch (error) {
        console.error('Error logging view event:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const getAvgSessionDuration= async (req, res) => {

    try {
        const averageSessionDuration = await Session.aggregate([
            { $group: { _id: null, totalDuration: { $sum: '$duration' }, count: { $sum: 1 } } }, // Calculate total duration and count of sessions
            { $project: { _id: 0, averageDuration: { $divide: ['$totalDuration', '$count'] } } } // Calculate average duration
        ]);

        res.json(averageSessionDuration[0]); // Return the result
    } catch (error) {
        console.error('Error fetching average session duration:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
    const activeuserscount= async (req, res) => {

    try {
        const activeUsersCount = await VendorData.countDocuments({ lastActivity: { $gt: new Date(Date.now() - 2 * 60 * 1000) } });
        //   console.log(activeUsersCount, 'from active users count')
        res.json(activeUsersCount);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
}
module.exports = {
    search,
    getsearchcount,
    popularSearches,
    click,
    getclickcount,
    popularClicks,
    vendorPopularClicks,
    view,
    getviewcount,
    popularViews,
    vendorPopularViews,
    popularCategories,
    sendsessionduration,
    getAvgSessionDuration,
    activeuserscount,
  };