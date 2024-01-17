const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY)

const port = process.env.PORT || 5000;
// const port = 5000;

// middleware
app.use(cors());
app.use(express.json());

const verifyJWT = async (req, res, next) => {
    const authorization = req.headers.authorization;
    // console.log(authorization);

    if (!authorization) {
        return res.status(401).send({ error: true, message: 'unauthorized access from !authorization' });
    }
    const token = authorization.split(' ')[1]; //Bearer <token>

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send({ error: true, message: 'unauthorized access from jwt.verify' });
        }
        req.decoded = decoded;
        next();
    })
}


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.dudbtcu.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();



        const menuCollection = client.db("bistroDb").collection("menu");
        const cartCollection = client.db("bistroDb").collection("carts");
        const usersCollection = client.db("bistroDb").collection("users");
        const paymentCollection = client.db("bistroDb").collection("payments");

        // jwt
        app.post('/jwt', (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
                expiresIn: '12h'
            });
            res.send({ token });
        })

        // check admin or not
        // Warning: use verifyJWT before using verifyAdmin
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            if (user?.role !== 'admin') {
                return res.status(403).send({ error: true, message: 'forbidden access' });
            }
            next();
        }


        /**
         * 0. do not show secure links to those who should not see the links isAdmin? <> : <>
         * 1. use jwt token: verifyJWT
         * 2. use verifyAdmin middleware
         */
        // users api - need to secure
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        })

        app.post('/users', async (req, res) => {
            const user = req.body;
            // console.log(user.email);
            const query = { email: user.email };
            const existingUser = await usersCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'user already exists' });
            }
            const result = await usersCollection.insertOne(user);
            res.send(result);
        })

        // admin
        // mainly return admin is true or false
        app.get('/users/admin/:email', verifyJWT, async (req, res) => {

            // we can use middleware for this like verifyAdmin
            const email = req.params.email;
            if (req.decoded.email !== email) {
                req.send({ admin: false })
            }
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const result = { admin: user?.role === 'admin' };
            res.send(result);
        })

        app.patch('/users/admin/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    role: 'admin'
                }
            }
            const result = await usersCollection.updateOne(filter, updatedDoc);
            res.send(result);
        })


        // menu api
        app.get('/menu', async (req, res) => {
            const result = await menuCollection.find().toArray();
            res.send(result);
        })

        app.post('/menu', verifyJWT, verifyAdmin, async (req, res) => {
            const newItem = req.body;
            const result = await menuCollection.insertOne(newItem)
            res.send(result)
        })

        app.delete('/menu/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            // console.log(id);
            const query = { _id: new ObjectId(id) }
            const result = await menuCollection.deleteOne(query)
            res.send(result)
        })


        // cart api

        app.get('/carts', verifyJWT, async (req, res) => {
            // console.log('hit carts');
            const decodedEmail = req.decoded.email; // req.decoded = email, iat, exp
            // console.log('came back after verify', decoded);
            const email = req.query.email;
            // console.log(email, decodedEmail);
            if (!email) {
                res.send([]);
            }
            // to prevent one verify token and get other's data
            if (email !== decodedEmail) {
                return res.status(403).send({ error: true, message: 'forbidden access' });
            }

            const query = { email: email };
            const result = await cartCollection.find(query).toArray();
            // console.log(result);
            res.send(result);

        })

        app.post('/carts', async (req, res) => {
            const item = req.body;
            const result = await cartCollection.insertOne(item);
            res.send(result);
        })

        app.delete('/carts/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await cartCollection.deleteOne(query);
            res.send(result);
        })



        // create payment intent
        app.post('/create-payment-intent', verifyJWT, async (req, res) => {
            const { price } = req.body;
            const amount = price * 100;
            // console.log(price, amount);

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: "usd",
                payment_method_types: ['card']
            })
            res.send({
                clientSecret: paymentIntent.client_secret
            })
        })


        // payment related api
        app.post('/payments', verifyJWT, async (req, res) => {
            const payment = req.body;
            const insertResult = await paymentCollection.insertOne(payment);

            // delete query
            const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) } }
            const deleteResult = await cartCollection.deleteMany(query)

            res.send({ insertResult, deleteResult })
        })


        app.get('/admin-states', verifyJWT, verifyAdmin, async (req, res) => {
            const users = await usersCollection.estimatedDocumentCount();
            const products = await menuCollection.estimatedDocumentCount();
            const orders = await paymentCollection.estimatedDocumentCount();

            // best way to get sum of the price field is to use group and sum operator

            // await collectionName.aggregate([
            //     {
            //         $group:{
            //             _id: null,
            //             total: {$sum: '$price'}
            //         }
            //     }
            // ])

            // or
            // load all the data and sum
            const payments = await paymentCollection.find().toArray();
            const revenue = payments.reduce((sum, payment) => sum + payment.price, 0)

            res.send({
                users,
                products,
                orders,
                revenue
            })
        })



        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);




app.get('/', (req, res) => {
    res.send("server is running");
})


// const errorHandler = ((err, req, res, next) => {
//     if (res.headersSent) {
//         return next(err)
//     }
//     res.send({ error: err, message: 'error from my custom errorHndler' });
// })
// app.use(errorHandler);



app.listen(port, () => {
    console.log(`Server running on port ${port}`);
})