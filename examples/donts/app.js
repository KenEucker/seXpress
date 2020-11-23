const sexpress = require('../..')

const app = sexpress({ name: 'old' })
const app2 = sexpress({ name: 'new', run: true })
const app3 = sexpress()
const app4 = sexpress({ name: 'never' })

console.log('NONE:', {
    app1: app.isRunning(),
    ap2: app2.isRunning(),
    app3: app3.isRunning(),
    app4: app4.isRunning(),
})

app.run().then(async () => {
    console.log('TWO:', {
        app1: app.isRunning(),
        app2: app2.isRunning(),
        app3: app3.isRunning(),
        app4: app4.isRunning(),
    })
    await app3.run().then(() => {
        console.log('FOUR:', {
            app1: app.isRunning(),
            app2: app2.isRunning(),
            app3: app3.isRunning(),
            app4: app4.isRunning(),
        })
    })
    console.log('THREE:', {
        app1: app.isRunning(),
        app2: app2.isRunning(),
        app3: app3.isRunning(),
        app4: app4.isRunning(),
    })
})

console.log('ONE:', {
    app1: app.isRunning(),
    app2: app2.isRunning(),
    app3: app3.isRunning(),
    app4: app4.isRunning(),
})
